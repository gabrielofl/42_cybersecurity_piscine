#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <regex>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <curl/curl.h>

struct MemoryStruct {
    char* memory;
    size_t size;
};

static std::set<std::string> visited_urls;
static std::set<std::string> downloaded_images;

static bool recursive = false;
static int max_depth = 5;
static std::string save_path = "./data/";
static std::string base_url;

static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    MemoryStruct* mem = static_cast<MemoryStruct*>(userp);

    char* ptr = static_cast<char*>(realloc(mem->memory, mem->size + realsize + 1));
    if (!ptr) {
        std::cerr << "Malloc failure\n";
        return 0;
    }

    mem->memory = ptr;
    std::memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string get_origin(const std::string& url) {
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return "";
    }

    size_t host_start = scheme_end + 3;
    size_t host_end = url.find('/', host_start);
    if (host_end == std::string::npos) {
        return url;
    }

    return url.substr(0, host_end);
}

static std::string get_path_from_url(const std::string& url) {
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return "/";
    }

    size_t host_start = scheme_end + 3;
    size_t path_start = url.find('/', host_start);
    if (path_start == std::string::npos) {
        return "/";
    }

    return url.substr(path_start);
}

static bool same_origin(const std::string& a, const std::string& b) {
    return get_origin(a) == get_origin(b);
}

static std::string get_absolute_url(const std::string& current_url, const std::string& relative_url) {
    if (relative_url.empty()) {
        return "";
    }

    if (relative_url.find("http://") == 0 || relative_url.find("https://") == 0) {
        return relative_url;
    }

    if (relative_url.find("//") == 0) {
        size_t scheme_end = current_url.find("://");
        if (scheme_end != std::string::npos) {
            return current_url.substr(0, scheme_end) + ":" + relative_url;
        }
        return "https:" + relative_url;
    }

    std::string origin = get_origin(current_url);
    if (origin.empty()) {
        return "";
    }

    if (relative_url[0] == '/') {
        return origin + relative_url;
    }

    size_t query_pos = current_url.find('?');
    std::string clean_current = (query_pos == std::string::npos) ? current_url : current_url.substr(0, query_pos);

    size_t last_slash = clean_current.rfind('/');
    if (last_slash == std::string::npos) {
        return origin + "/" + relative_url;
    }

    return clean_current.substr(0, last_slash + 1) + relative_url;
}

static std::string get_filename_from_url(const std::string& url) {
    size_t last_slash = url.rfind('/');
    std::string filename = (last_slash == std::string::npos) ? url : url.substr(last_slash + 1);

    size_t q = filename.find('?');
    if (q != std::string::npos) {
        filename = filename.substr(0, q);
    }

    size_t h = filename.find('#');
    if (h != std::string::npos) {
        filename = filename.substr(0, h);
    }

    if (filename.empty()) {
        return "unnamed";
    }
    return filename;
}

static bool has_image_extension(const std::string& url) {
    std::string lower = to_lower(url);

    std::vector<std::string> exts = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp"
    };

    for (const std::string& ext : exts) {
        size_t pos = lower.find(ext);
        if (pos == std::string::npos) {
            continue;
        }

        size_t end = pos + ext.size();
        if (end == lower.size() ||
            lower[end] == '?' ||
            lower[end] == '#' ||
            lower[end] == '"' ||
            lower[end] == '\'' ||
            lower[end] == ' ' ||
            lower[end] == ',') {
            return true;
        }
    }

    return false;
}

static bool should_skip_link(const std::string& url) {
    std::string lower = to_lower(url);

    if (lower.empty()) return true;
    if (lower[0] == '#') return true;
    if (lower.find("javascript:") == 0) return true;
    if (lower.find("mailto:") == 0) return true;
    if (lower.find("tel:") == 0) return true;

    static const std::vector<std::string> blocked_exts = {
        ".js", ".css", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".pdf", ".zip", ".mp4", ".webm", ".xml", ".json"
    };

    for (const std::string& ext : blocked_exts) {
        if (lower.find(ext) != std::string::npos) {
            return true;
        }
    }

    return false;
}

struct DownloadResult {
    std::string body;
    std::string content_type;
    long http_status = 0;
    bool ok = false;
    CURLcode curl_code = CURLE_OK;
    std::string error_message;
};

static DownloadResult download_text(const std::string& url) {
    DownloadResult result;

    CURL* curl = curl_easy_init();
    if (!curl) {
        result.error_message = "Failed to initialize curl";
        return result;
    }

    MemoryStruct chunk;
    chunk.memory = static_cast<char*>(malloc(1));
    chunk.size = 0;

    char errbuf[CURL_ERROR_SIZE] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Spider");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode res = curl_easy_perform(curl);
    result.curl_code = res;

    if (res != CURLE_OK) {
        result.error_message = errbuf[0] ? errbuf : curl_easy_strerror(res);
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return result;
    }

    char* content_type = nullptr;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_status);

    result.body.assign(chunk.memory, chunk.size);
    result.content_type = content_type ? content_type : "";
    result.ok = true;

    free(chunk.memory);
    curl_easy_cleanup(curl);
    return result;
}

class RobotsTxtParser {
private:
    std::string origin;
    bool loaded = false;

    std::map<std::string, std::vector<std::string>> allowed_paths;
    std::map<std::string, std::vector<std::string>> disallowed_paths;

    static bool starts_with(const std::string& s, const std::string& prefix) {
        return s.rfind(prefix, 0) == 0;
    }

    static bool path_matches(const std::string& path, const std::string& rule) {
        if (rule.empty()) {
            return false;
        }

        if (rule == "/") {
            return true;
        }

        return starts_with(path, rule);
    }

    static std::string extract_value(const std::string& line) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            return "";
        }
        return trim(line.substr(colon + 1));
    }

public:
    explicit RobotsTxtParser(const std::string& start_url) {
        origin = get_origin(start_url);
    }

    bool fetch_and_parse() {
    if (origin.empty()) {
        std::cerr << "Invalid base URL.\n";
        return false;
    }

    std::string robots_url = origin + "/robots.txt";
    DownloadResult res = download_text(robots_url);

    if (!res.ok) {
        if (res.curl_code == CURLE_COULDNT_RESOLVE_HOST) {
            std::cerr << "Error: could not resolve host for " << origin << "\n";
            std::cerr << "Please check the URL and your internet connection.\n";
            return false;
        }

        if (res.curl_code == CURLE_COULDNT_CONNECT) {
            std::cerr << "Error: could not connect to " << origin << "\n";
            return false;
        }

        std::cout << "No robots.txt found for " << origin << " (allowing by default)\n";
        loaded = true;
        return true;
    }

    if (res.http_status >= 400 || res.body.empty()) {
        std::cout << "No robots.txt found for " << origin << " (allowing by default)\n";
        loaded = true;
        return true;
    }

        std::istringstream stream(res.body);
        std::string line;
        std::string current_agent = "*";
        bool relevant_section = false;

        while (std::getline(stream, line)) {
            size_t comment_pos = line.find('#');
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }

            line = trim(line);
            if (line.empty()) {
                continue;
            }

            std::string lower_line = to_lower(line);

            if (lower_line.rfind("user-agent:", 0) == 0) {
                current_agent = extract_value(line);
                std::string lower_agent = to_lower(current_agent);
                relevant_section = (lower_agent == "*" || lower_agent == to_lower("Spider"));
            }
            else if (relevant_section && lower_line.rfind("allow:", 0) == 0) {
                std::string path = extract_value(line);
                if (!path.empty()) {
                    allowed_paths[current_agent].push_back(path);
                }
            }
            else if (relevant_section && lower_line.rfind("disallow:", 0) == 0) {
                std::string path = extract_value(line);
                if (!path.empty()) {
                    disallowed_paths[current_agent].push_back(path);
                }
            }
        }

        loaded = true;
        std::cout << "Robots.txt loaded for " << origin << "\n";
        return true;
    }

    bool is_allowed(const std::string& url) const {
        if (!loaded) {
            return true;
        }

        std::string path = get_path_from_url(url);
        std::vector<std::string> agents = {"Spider", "*"};

        size_t best_allow_len = 0;
        size_t best_disallow_len = 0;

        for (const std::string& agent : agents) {
            auto allow_it = allowed_paths.find(agent);
            if (allow_it != allowed_paths.end()) {
                for (const std::string& rule : allow_it->second) {
                    if (path_matches(path, rule) && rule.size() > best_allow_len) {
                        best_allow_len = rule.size();
                    }
                }
            }

            auto disallow_it = disallowed_paths.find(agent);
            if (disallow_it != disallowed_paths.end()) {
                for (const std::string& rule : disallow_it->second) {
                    if (path_matches(path, rule) && rule.size() > best_disallow_len) {
                        best_disallow_len = rule.size();
                    }
                }
            }
        }

        if (best_allow_len >= best_disallow_len) {
            return true;
        }

        std::cout << "Blocked by robots.txt: " << url << "\n";
        return false;
    }
};

static RobotsTxtParser* robots_parser = nullptr;

static std::vector<std::string> split_srcset(const std::string& srcset_value) {
    std::vector<std::string> urls;
    std::stringstream ss(srcset_value);
    std::string item;

    while (std::getline(ss, item, ',')) {
        std::stringstream part(item);
        std::string url;
        part >> url;
        if (!url.empty()) {
            urls.push_back(url);
        }
    }

    return urls;
}

static std::vector<std::string> extract_image_urls(const std::string& html, const std::string& page_url) {
    std::vector<std::string> img_urls;
    std::set<std::string> seen;

    std::regex img_tag_regex(R"(<img[^>]*>)", std::regex_constants::icase);
    std::regex src_regex(R"(src\s*=\s*["']([^"']+)["'])", std::regex_constants::icase);
    std::regex srcset_regex(R"(srcset\s*=\s*["']([^"']+)["'])", std::regex_constants::icase);

    std::sregex_iterator tag_it(html.begin(), html.end(), img_tag_regex);
    std::sregex_iterator tag_end;

    while (tag_it != tag_end) {
        std::string img_tag = tag_it->str();

        std::smatch src_match;
        if (std::regex_search(img_tag, src_match, src_regex)) {
            std::string raw = src_match[1].str();
            if (has_image_extension(raw)) {
                std::string abs = get_absolute_url(page_url, raw);
                if (!abs.empty() && seen.insert(abs).second) {
                    img_urls.push_back(abs);
                }
            }
        }

        std::smatch srcset_match;
        if (std::regex_search(img_tag, srcset_match, srcset_regex)) {
            std::string srcset_value = srcset_match[1].str();
            std::vector<std::string> urls = split_srcset(srcset_value);

            for (const std::string& raw : urls) {
                if (has_image_extension(raw)) {
                    std::string abs = get_absolute_url(page_url, raw);
                    if (!abs.empty() && seen.insert(abs).second) {
                        img_urls.push_back(abs);
                    }
                }
            }
        }

        ++tag_it;
    }

    return img_urls;
}

static std::vector<std::string> extract_page_links(const std::string& html, const std::string& page_url) {
    std::vector<std::string> links;
    std::set<std::string> seen;

    std::regex a_regex(R"(<a[^>]*href\s*=\s*["']([^"']+)["'])", std::regex_constants::icase);
    std::sregex_iterator it(html.begin(), html.end(), a_regex);
    std::sregex_iterator end;

    while (it != end) {
        std::string raw = (*it)[1].str();

        if (!should_skip_link(raw)) {
            std::string abs = get_absolute_url(page_url, raw);

            if (!abs.empty() &&
                same_origin(abs, base_url) &&
                !has_image_extension(abs) &&
                !should_skip_link(abs) &&
                seen.insert(abs).second) {
                links.push_back(abs);
            }
        }

        ++it;
    }

    return links;
}

static void download_image(const std::string& url) {
    if (downloaded_images.count(url)) {
        return;
    }
    downloaded_images.insert(url);

    if (!std::filesystem::exists(save_path)) {
        std::filesystem::create_directories(save_path);
    }

    std::string filename = get_filename_from_url(url);
    if (filename.empty()) {
        return;
    }

    std::string save_to = save_path + filename;

    FILE* fp = fopen(save_to.c_str(), "wb");
    if (!fp) {
        std::cerr << "Failed to open file: " << save_to << "\n";
        return;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        fclose(fp);
        return;
    }

    char errbuf[CURL_ERROR_SIZE] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Spider");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
        if (errbuf[0]) {
            std::cerr << "details: " << errbuf << "\n";
        }
        fclose(fp);
        curl_easy_cleanup(curl);
        std::filesystem::remove(save_to);
        return;
    }

    std::cout << "Downloaded: " << filename << "\n";

    fclose(fp);
    curl_easy_cleanup(curl);
}

static void execute(const std::string& url, int depth) {
    if (depth < 0) {
        return;
    }

    if (visited_urls.count(url)) {
        return;
    }
    visited_urls.insert(url);

    if (!same_origin(url, base_url)) {
        return;
    }

    if (!robots_parser->is_allowed(url)) {
        return;
    }

    std::cout << "spider: " << url << " (depth: " << depth << ")\n";

    DownloadResult page = download_text(url);
    if (!page.ok) {
        return;
    }

    std::cout << "HTTP status: " << page.http_status << "\n";

    std::string lower_ct = to_lower(page.content_type);
    bool is_html = lower_ct.find("text/html") != std::string::npos;

    if (!is_html) {
        return;
    }

    std::vector<std::string> img_urls = extract_image_urls(page.body, url);
    for (const std::string& img_url : img_urls) {
        if (!robots_parser->is_allowed(img_url)) {
            continue;
        }
        if (has_image_extension(img_url)) {
            download_image(img_url);
        }
    }

    if (!recursive || depth == 0) {
        return;
    }

    std::vector<std::string> links = extract_page_links(page.body, url);
    for (const std::string& link : links) {
        if (!visited_urls.count(link) && robots_parser->is_allowed(link)) {
            execute(link, depth - 1);
        }
    }
}

void parse_options(int argc, char* argv[]) {
    recursive = false;
    max_depth = 5;
    save_path = "./data/";
    base_url.clear();

    bool saw_r = false;
    bool saw_l = false;
    bool saw_p = false;
    bool saw_url = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-r") {
            if (saw_r) {
                throw std::runtime_error("Option -r was provided more than once.");
            }
            recursive = true;
            saw_r = true;
        }
        else if (arg == "-l") {
            if (saw_l) {
                throw std::runtime_error("Option -l was provided more than once.");
            }
            saw_l = true;

            if (i + 1 >= argc) {
                throw std::runtime_error("Option -l requires a numeric value.");
            }

            std::string value = argv[++i];

            if (value.empty()) {
                throw std::runtime_error("Option -l requires a numeric value.");
            }

            size_t start = 0;
            if (value[0] == '-') {
                start = 1;
            }

            if (start == value.size()) {
                throw std::runtime_error("Invalid depth value for -l: " + value);
            }

            for (size_t j = start; j < value.size(); ++j) {
                if (!std::isdigit(static_cast<unsigned char>(value[j]))) {
                    throw std::runtime_error("Invalid depth value for -l: " + value);
                }
            }

            int parsed_depth = 0;
            try {
                parsed_depth = std::stoi(value);
            } catch (...) {
                throw std::runtime_error("Depth value for -l is out of range: " + value);
            }

            if (parsed_depth < 0) {
                throw std::runtime_error("Depth for -l cannot be negative.");
            }

            max_depth = parsed_depth;
        }
        else if (arg == "-p") {
            if (saw_p) {
                throw std::runtime_error("Option -p was provided more than once.");
            }
            saw_p = true;

            if (i + 1 >= argc) {
                throw std::runtime_error("Option -p requires a path value.");
            }

            std::string value = argv[++i];

            if (value.empty()) {
                throw std::runtime_error("Option -p requires a path value.");
            }

            if (value == "-r" || value == "-l" || value == "-p" ||
                value == "-h" || value == "--help") {
                throw std::runtime_error("Invalid path for -p: " + value);
            }

            save_path = value;
            if (!save_path.empty() && save_path.back() != '/' && save_path.back() != '\\') {
                save_path += '/';
            }
        }
        else if (!arg.empty() && arg[0] == '-') {
            throw std::runtime_error("Unknown option: " + arg);
        }
        else {
            if (saw_url) {
                throw std::runtime_error("Multiple URLs provided. Please provide exactly one URL.");
            }

            base_url = arg;
            saw_url = true;
        }
    }

    if (!saw_url) {
        throw std::runtime_error("URL not provided.");
    }

    if (saw_l && !saw_r) {
        throw std::runtime_error("Option -l can only be used together with -r.");
    }

    if (!recursive) {
        max_depth = 0;
    }
}

static void print_help() {
    std::cout
        << "Usage: ./spider [-r] [-l N] [-p PATH] URL\n"
        << "  -r         Recursively download images from linked pages.\n"
        << "  -l N       Maximum recursion depth. Default: 5.\n"
        << "  -p PATH    Directory to save images. Default: ./data/\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc == 1) {
            print_help();
            return 0;
        }

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                print_help();
                return 0;
            }
        }

        parse_options(argc, argv);

        curl_global_init(CURL_GLOBAL_DEFAULT);

        robots_parser = new RobotsTxtParser(base_url);
		if (!robots_parser->fetch_and_parse()) {
			delete robots_parser;
			robots_parser = nullptr;
			curl_global_cleanup();
			return 1;
		}

        execute(base_url, recursive ? max_depth : 0);

        delete robots_parser;
        robots_parser = nullptr;

        curl_global_cleanup();
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        std::cerr << "Run ./spider --help for usage.\n";
        return 1;
    }
}
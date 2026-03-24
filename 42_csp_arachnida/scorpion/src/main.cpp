#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <map>
#include <ctime>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-tag.h>

struct ImageMetadata {
    std::string filename;
    std::string filepath;
    size_t file_size;
    std::string file_type;
    std::string creation_date;
    std::string modification_date;
    std::map<std::string, std::string> exif_data;
};

std::string get_file_extension(const std::string& filename) {
    size_t dot_pos = filename.rfind('.');
    if (dot_pos == std::string::npos) {
        return "";
    }
    std::string ext = filename.substr(dot_pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

bool is_supported_image(const std::string& filename) {
    std::string ext = get_file_extension(filename);
    return (ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "gif" || ext == "bmp");
}

std::string format_timestamp(time_t timestamp) {
    char buffer[80];
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return std::string(buffer);
}

void exif_content(ExifContent* content, void* user_data) {
    std::map<std::string, std::string>* exif_data = (std::map<std::string, std::string>*)user_data;
    
    exif_content_foreach_entry(content, [](ExifEntry* entry, void* data) -> void {
        std::map<std::string, std::string>* exif_map = (std::map<std::string, std::string>*)data;
        
        char buffer[1024];
        exif_entry_get_value(entry, buffer, sizeof(buffer));
        
        const char* tag_name = exif_tag_get_name(entry->tag);
        if (tag_name && strlen(buffer) > 0) {
            (*exif_map)[std::string(tag_name)] = std::string(buffer);
        }
    }, exif_data);
}

void extract_exif_data(const std::string& filepath, std::map<std::string, std::string>& exif_data) {
    ExifData* exif_data_ptr = exif_data_new_from_file(filepath.c_str());
    if (!exif_data_ptr) {
        exif_data["Note"] = "No EXIF data found";
        return;
    }

    exif_data_foreach_content(exif_data_ptr, exif_content, &exif_data);
    exif_data_unref(exif_data_ptr);

    if (exif_data.empty()) {
        exif_data["Note"] = "No EXIF tags found";
    }
}

bool analyze_image(const std::string& filepath, ImageMetadata& metadata) {
    if (!std::filesystem::exists(filepath)) {
        std::cerr << "File does not exist: " << filepath << std::endl;
        return false;
    }
    
    metadata.filename = std::filesystem::path(filepath).filename().string();
    metadata.filepath = std::filesystem::absolute(filepath).string();
    metadata.file_type = get_file_extension(filepath);
    
    std::ifstream file(filepath, std::ifstream::ate | std::ifstream::binary);
    metadata.file_size = file.tellg();
    file.close();
    
    auto ftime = std::filesystem::last_write_time(filepath);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    metadata.modification_date = format_timestamp(std::chrono::system_clock::to_time_t(sctp));
    
    metadata.creation_date = metadata.modification_date;
    
    extract_exif_data(filepath, metadata.exif_data);
    
    return true;
}

void print_metadata(const ImageMetadata& metadata) {
    std::cout << "Filename: " << metadata.filename << "\n";
    std::cout << "File Path: " << metadata.filepath << "\n";
    std::cout << "File Type: " << metadata.file_type << "\n";
    std::cout << "File Size (bytes): " << metadata.file_size << "\n";
    std::cout << "Creation Date: " << metadata.creation_date << "\n";
    std::cout << "Modification Date: " << metadata.modification_date << "\n";

    std::cout << "EXIF Data\n";
    for (const auto& [tag, value] : metadata.exif_data) {
        std::cout << tag << ": " << value << "\n";
    }
    std::cout << "-----------------\n";
}

static void print_help() {
    std::cout << "Usage: ./scorpion FILE1 [FILE2 ...]\n";
    std::cout << "Extracts and displays metadata from image files.\n";
    std::cout << "Supported formats: .jpg, .jpeg, .png, .gif, .bmp\n";
}

int main(int argc, char* argv[]) {
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
    
    std::vector<ImageMetadata> analyzed_images;
    
    for (int i = 1; i < argc; ++i) {
        std::string filepath = argv[i];
        
        if (!is_supported_image(filepath)) {
            std::cerr << "Warning: " << filepath << " is not a supported image format. Skipping." << std::endl;
            continue;
        }
        
        ImageMetadata metadata;
        if (analyze_image(filepath, metadata)) {
            analyzed_images.push_back(metadata);
        }
    }

    if (analyzed_images.empty()) {
        std::cout << "\nNo valid image files." << std::endl;
        return 1;
    }
    
    std::cout << "\nscorpion\n";
    std::cout << "Analyzed " << analyzed_images.size() << " image file(s):\n";
    
    for (const auto& metadata : analyzed_images) {
        print_metadata(metadata);
    }
    
    return 0;
}
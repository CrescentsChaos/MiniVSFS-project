#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define BS 4096u
#define INODE_SIZE 128u
#define ROOT_INO 1u
#define DIRECT_MAX 12
#pragma pack(push, 1)

typedef struct {
    // CREATE YOUR SUPERBLOCK HERE
    // ADD ALL FIELDS AS PROVIDED BY THE SPECIFICATION

    // THIS FIELD SHOULD STAY AT THE END
    // ALL OTHER FIELDS SHOULD BE ABOVE THIS
    uint32_t magic;               // 0x4D565346
    uint32_t version;             // 1
    uint32_t block_size;          // 4096
    uint64_t total_blocks;        
    uint64_t inode_count;         
    uint64_t inode_bitmap_start;  
    uint64_t inode_bitmap_blocks; 
    uint64_t data_bitmap_start;   
    uint64_t data_bitmap_blocks;  
    uint64_t inode_table_start;   
    uint64_t inode_table_blocks; 
    uint64_t data_region_start;   
    uint64_t data_region_blocks;  
    uint64_t root_inode;          // 1
    uint64_t mtime_epoch;         // build time
    uint32_t flags; 
    uint32_t checksum;            // crc32(superblock[0..4091])
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block");

#pragma pack(push,1)
typedef struct {
    // CREATE YOUR INODE HERE
    // IF CREATED CORRECTLY, THE STATIC_ASSERT ERROR SHOULD BE GONE

    // THIS FIELD SHOULD STAY AT THE END
    // ALL OTHER FIELDS SHOULD BE ABOVE THIS
    uint16_t mode;                // file type and permissions
    uint16_t links;               // number of hard links
    uint32_t uid;                 // 0
    uint32_t gid;                 // 0
    uint64_t size_bytes;          
    uint64_t atime;               // access time
    uint64_t mtime;               // modification time
    uint64_t ctime;               // creation time
    uint32_t direct[DIRECT_MAX];  
    uint32_t reserved_0;          // 0
    uint32_t reserved_1;          // 0
    uint32_t reserved_2;          // 0
    uint32_t proj_id;             // 13
    uint32_t uid16_gid16;         // 0
    uint64_t xattr_ptr;           // 0
    uint64_t inode_crc;   // low 4 bytes store crc32 of bytes [0..119]; high 4 bytes 0

} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    // CREATE YOUR DIRECTORY ENTRY STRUCTURE HERE
    // IF CREATED CORRECTLY, THE STATIC_ASSERT ERROR SHOULD BE GONE
    uint32_t inode_no;            // inode number (0 if free)
    uint8_t  type;                // 1=file, 2=dir
    char     name[58]; 
    uint8_t  checksum; // XOR of bytes 0..62
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch");


// ==========================DO NOT CHANGE THIS PORTION=========================
// These functions are there for your help. You should refer to the specifications to see how you can use them.
// ====================================CRC32====================================
uint32_t CRC32_TAB[256];
void crc32_init(void){
    for (uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        CRC32_TAB[i]=c;
    }
}
uint32_t crc32(const void* data, size_t n){
    const uint8_t* p=(const uint8_t*)data; uint32_t c=0xFFFFFFFFu;
    for(size_t i=0;i<n;i++) c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8);
    return c ^ 0xFFFFFFFFu;
}
// ====================================CRC32====================================

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
static uint32_t superblock_crc_finalize(superblock_t *sb) {
    sb->checksum = 0;
    uint32_t s = crc32((void *) sb, BS - 4);
    sb->checksum = s;
    return s;
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void inode_crc_finalize(inode_t* ino){
    uint8_t tmp[INODE_SIZE]; memcpy(tmp, ino, INODE_SIZE);
    // zero crc area before computing
    memset(&tmp[120], 0, 8);
    uint32_t c = crc32(tmp, 120);
    ino->inode_crc = (uint64_t)c; // low 4 bytes carry the crc
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void dirent_checksum_finalize(dirent64_t* de) {
    const uint8_t* p = (const uint8_t*)de;
    uint8_t x = 0;
    for (int i = 0; i < 63; i++) x ^= p[i];   // covers ino(4) + type(1) + name(58)
    de->checksum = x;
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --input <input.img> --output <output.img> --file <filename>\n", prog);
}

// Find first free inode
uint32_t find_free_inode(uint8_t *inode_bitmap, uint64_t inode_count) {
    for (uint64_t byte_idx = 0; byte_idx < (inode_count + 7) / 8; byte_idx++) {
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            uint32_t inode_num = byte_idx * 8 + bit_idx + 1; // 1-indexed
            if (inode_num > inode_count) break;
            
            if (!(inode_bitmap[byte_idx] & (1 << bit_idx))) {
                return inode_num;
            }
        }
    }
    return 0; // no free inode
}

// Find first free data block
uint32_t find_free_data_block(uint8_t *data_bitmap, uint64_t data_region_blocks) {
    for (uint64_t byte_idx = 0; byte_idx < (data_region_blocks + 7) / 8; byte_idx++) {
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            uint32_t block_num = byte_idx * 8 + bit_idx;
            if (block_num >= data_region_blocks) break;
            
            if (!(data_bitmap[byte_idx] & (1 << bit_idx))) {
                return block_num;
            }
        }
    }
    return 0xFFFFFFFF; // no free block
}

// Set bit in bitmap
void set_bitmap_bit(uint8_t *bitmap, uint32_t bit_num) {
    uint32_t byte_idx = bit_num / 8;
    uint32_t bit_idx = bit_num % 8;
    bitmap[byte_idx] |= (1 << bit_idx);
}

int main(int argc, char *argv[]) {
    crc32_init();
    // WRITE YOUR DRIVER CODE HERE
    // PARSE YOUR CLI PARAMETERS
    // THEN ADD THE SPECIFIED FILE TO YOUR FILE SYSTEM
    // UPDATE THE .IMG FILE ON DISK
    
    char *input_file = NULL;
    char *output_file = NULL;
    char *file_to_add = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            file_to_add = argv[++i];
        } else {
            usage(argv[0]);
    return 1;
}
    }
    // Validate arguments
    if (!input_file || !output_file || !file_to_add) {
        usage(argv[0]);
        return 1;
    }
    
    // Check if the file to add exists
    struct stat file_stat;
    if (stat(file_to_add, &file_stat) != 0) {
        fprintf(stderr, "Error: File '%s' not found: %s\n", file_to_add, strerror(errno));
        return 1;
    }
    
    if (!S_ISREG(file_stat.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a regular file\n", file_to_add);
        return 1;
    }
    
    // Check file name length
    const char *basename = strrchr(file_to_add, '/');
    if (basename) basename++; else basename = file_to_add;
    
    if (strlen(basename) >= 58) {
        fprintf(stderr, "Error: Filename too long (max 57 characters)\n");
        return 1;
    }
    
    // Open input image
    FILE *input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        fprintf(stderr, "Error: Cannot open input image '%s': %s\n", input_file, strerror(errno));
        return 1;
    }
    
    // Read superblock
    superblock_t sb;
    if (fread(&sb, sizeof(sb), 1, input_fp) != 1) {
        fprintf(stderr, "Error: Cannot read superblock\n");
        fclose(input_fp);
        return 1;
    }
    
    // Validate magic
    if (sb.magic != 0x4D565346) {
        fprintf(stderr, "Error: Invalid filesystem magic\n");
        fclose(input_fp);
        return 1;
    }
    
    // Checks if file is too large
    uint64_t file_size = file_stat.st_size;
    uint64_t blocks_needed = (file_size + BS - 1) / BS;
    if (blocks_needed > DIRECT_MAX) {
        fprintf(stderr, "Error: File too large (max %d blocks)\n", DIRECT_MAX);
        fclose(input_fp);
        return 1;
    }
    
    // Read entire filesystem into memory
    fseek(input_fp, 0, SEEK_SET);
    uint8_t *fs_image = malloc(sb.total_blocks * BS);
    if (!fs_image) {
        fprintf(stderr, "Error: Cannot allocate memory\n");
        fclose(input_fp);
        return 1;
    }
    
    if (fread(fs_image, BS, sb.total_blocks, input_fp) != sb.total_blocks) {
        fprintf(stderr, "Error: Cannot read filesystem image\n");
        free(fs_image);
        fclose(input_fp);
        return 1;
    }
    fclose(input_fp);
    
    // Get pointers to different sections
    uint8_t *inode_bitmap = fs_image + sb.inode_bitmap_start * BS;
    uint8_t *data_bitmap = fs_image + sb.data_bitmap_start * BS;
    uint8_t *inode_table = fs_image + sb.inode_table_start * BS;
    uint8_t *data_region = fs_image + sb.data_region_start * BS;
    
    // Find free inode
    uint32_t free_inode_num = find_free_inode(inode_bitmap, sb.inode_count);
    if (free_inode_num == 0) {
        fprintf(stderr, "Error: No free inodes available\n");
        free(fs_image);
        return 1;
    }
    
    // Find free data blocks
    uint32_t file_blocks[DIRECT_MAX];
    uint32_t blocks_allocated = 0;
    
    for (uint64_t i = 0; i < blocks_needed; i++) {
        uint32_t free_block = find_free_data_block(data_bitmap, sb.data_region_blocks);
        if (free_block == 0xFFFFFFFF) {
            fprintf(stderr, "Error: Not enough free data blocks\n");
            free(fs_image);
            return 1;
        }
        file_blocks[blocks_allocated++] = free_block;
        set_bitmap_bit(data_bitmap, free_block);
    }
    
    // Mark inode as used
    set_bitmap_bit(inode_bitmap, free_inode_num - 1); // bitmap is 0-indexed
    
    // Create new inode
    inode_t *new_inode = (inode_t *)(inode_table + (free_inode_num - 1) * INODE_SIZE);
    memset(new_inode, 0, INODE_SIZE);
    
    new_inode->mode = 0100000; // regular file
    new_inode->links = 1;
    new_inode->uid = 0;
    new_inode->gid = 0;
    new_inode->size_bytes = file_size;
    new_inode->atime = time(NULL);
    new_inode->mtime = time(NULL);
    new_inode->ctime = time(NULL);
    
    for (uint32_t i = 0; i < blocks_allocated; i++) {
        new_inode->direct[i] = sb.data_region_start + file_blocks[i];
    }
    for (uint32_t i = blocks_allocated; i < DIRECT_MAX; i++) {
        new_inode->direct[i] = 0;
    }
    
    new_inode->proj_id = 13;
    new_inode->uid16_gid16 = 0;
    new_inode->xattr_ptr = 0;
    
    inode_crc_finalize(new_inode);
    
    // Read the file content and write to data blocks
    FILE *file_fp = fopen(file_to_add, "rb");
    if (!file_fp) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", file_to_add, strerror(errno));
        free(fs_image);
        return 1;
    }
    
    uint64_t remaining_bytes = file_size;
    for (uint32_t i = 0; i < blocks_allocated; i++) {
        uint8_t *block_ptr = data_region + file_blocks[i] * BS;
        size_t bytes_to_read = (remaining_bytes > BS) ? BS : remaining_bytes;
        
        if (fread(block_ptr, 1, bytes_to_read, file_fp) != bytes_to_read) {
            fprintf(stderr, "Error: Cannot read file content\n");
            fclose(file_fp);
            free(fs_image);
            return 1;
        }
        
        // Zero out the rest of the block if needed
        if (bytes_to_read < BS) {
            memset(block_ptr + bytes_to_read, 0, BS - bytes_to_read);
        }
        
        remaining_bytes -= bytes_to_read;
    }
    fclose(file_fp);
    
    // Update root directory
    inode_t *root_inode = (inode_t *)inode_table; // root is at index 0
    uint8_t *root_data = data_region; // root uses first data block
    
    // Find free directory entry slot
    dirent64_t *entries = (dirent64_t *)root_data;
    int entries_per_block = BS / sizeof(dirent64_t);
    int free_entry_idx = -1;
    
    // Look for free entry (inode_no == 0) or end of entries
    for (int i = 0; i < entries_per_block; i++) {
        if (entries[i].inode_no == 0) {
            free_entry_idx = i;
            break;
        }
    }
    
    if (free_entry_idx == -1) {
        fprintf(stderr, "Error: Root directory is full\n");
        free(fs_image);
        return 1;
    }
    
    // Checks if file already exists
    for (int i = 0; i < entries_per_block; i++) {
        if (entries[i].inode_no != 0 && strcmp(entries[i].name, basename) == 0) {
            fprintf(stderr, "Error: File '%s' already exists in filesystem\n", basename);
            free(fs_image);
            return 1;
        }
    }
    
    // Creates new directory entry
    dirent64_t *new_entry = &entries[free_entry_idx];
    memset(new_entry, 0, sizeof(dirent64_t));
    new_entry->inode_no = free_inode_num;
    new_entry->type = 1; // file
    strcpy(new_entry->name, basename);
    dirent_checksum_finalize(new_entry);
    
    // Updates root inode (increment links and size if needed)
    root_inode->links++; // new file refers to root via ..
    root_inode->size_bytes += sizeof(dirent64_t);
    root_inode->mtime = time(NULL);
    root_inode->atime = time(NULL);
    inode_crc_finalize(root_inode);
    
    // Updates superblock checksum
    superblock_t *sb_ptr = (superblock_t *)fs_image;
    superblock_crc_finalize(sb_ptr);
    
    // Writes output image
    FILE *output_fp = fopen(output_file, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output image '%s': %s\n", output_file, strerror(errno));
        free(fs_image);
        return 1;
    }
    
    if (fwrite(fs_image, BS, sb.total_blocks, output_fp) != sb.total_blocks) {
        fprintf(stderr, "Error: Cannot write output image\n");
        fclose(output_fp);
        free(fs_image);
        return 1;
    }
    
    fclose(output_fp);
    free(fs_image);
    
    printf("Successfully added file '%s' to filesystem\n", basename);
    printf("Allocated inode #%u and %u data block(s)\n", free_inode_num, blocks_allocated);
    
    return 0;
}
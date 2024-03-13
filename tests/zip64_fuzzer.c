#include "miniz.h"
#include <inttypes.h>
#include <stdint.h>

static char filename[260];
static unsigned char read_buf[1024 * 256];

static const size_t filename_max = sizeof(filename);
static const size_t read_buf_size = sizeof(read_buf);
static const size_t data_max = 1024 * 256;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > data_max)
        return 0;

    mz_uint flags = 0;
    int ret = 0;
    mz_zip_archive zip_reader;
    mz_zip_archive zip_writer;
    mz_zip_zero_struct(&zip_reader);
    mz_zip_zero_struct(&zip_writer);

    if (!mz_zip_reader_init_mem(&zip_reader, data, size, flags))
        return 0;
    if (!mz_zip_writer_init_heap_v2(&zip_writer, 0, size, flags | MZ_ZIP_FLAG_WRITE_ZIP64))
        return 0;

    mz_uint i, files;

    files = mz_zip_reader_get_num_files(&zip_reader);

    for (i = 0; i < files; i++)
    {
        mz_zip_clear_last_error(&zip_reader);

        if (mz_zip_reader_is_file_a_directory(&zip_reader, i))
            continue;

        mz_zip_validate_file(&zip_reader, i, MZ_ZIP_FLAG_VALIDATE_HEADERS_ONLY);

        if (mz_zip_reader_is_file_encrypted(&zip_reader, i))
            continue;

        mz_zip_clear_last_error(&zip_reader);

        mz_uint ret = mz_zip_reader_get_filename(&zip_reader, i, filename, filename_max);

        if (mz_zip_get_last_error(&zip_reader))
            continue;

        mz_zip_archive_file_stat file_stat = { 0 };
        mz_bool status = mz_zip_reader_file_stat(&zip_reader, i, &file_stat) != 0;

        if ((file_stat.m_method) && (file_stat.m_method != MZ_DEFLATED))
            continue;

        if (!mz_zip_writer_add_from_zip_reader(&zip_writer, &zip_reader, i))
            continue;

        if (!mz_zip_reader_extract_file_to_mem(&zip_writer, file_stat.m_filename, read_buf, read_buf_size, 0))
            continue;
    }

    if (!mz_zip_writer_finalize_archive(&zip_writer))
        return 1;

cleanup:
    mz_zip_reader_end(&zip_reader);
    mz_zip_writer_end(&zip_writer);
    return ret;
}

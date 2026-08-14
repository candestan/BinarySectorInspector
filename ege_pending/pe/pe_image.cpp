#include "pe/pe_image.h"

PeImage PeImage::load(const std::wstring& path)
{
    PeImage image;
    image.path = path;

    std::string load_error;
    auto file = PeFile::load(path, load_error);
    if (!file)
    {
        image.error = load_error;
        return image;
    }
    image.file = std::move(*file);
    image.headers = parse_headers(image.file);
    if (!image.headers.ok)
    {
        image.error = image.headers.error;
        return image;
    }
    image.headers_ok = true;
    image.imports = parse_imports(image.file, image.headers);
    image.exports = parse_exports(image.file, image.headers);
    image.relocs = parse_relocs(image.file, image.headers);
    image.tls = parse_tls(image.file, image.headers);
    image.resources = parse_resources(image.file, image.headers);
    image.debug = parse_debug(image.file, image.headers);
    image.entropy = compute_entropy(image.file, image.headers);
    image.strings = extract_strings(image.file);
    image.findings = collect_findings(
        image.file, image.headers, image.imports, image.tls, image.debug, image.entropy);
    return image;
}

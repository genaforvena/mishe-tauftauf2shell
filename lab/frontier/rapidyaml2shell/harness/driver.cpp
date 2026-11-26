#include <ryml.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace c4;

static void on_parse(csubstr msg, ryml::ErrorDataParse const &, void *)
{
    std::printf("PARSE_ERROR %.*s\n", (int)msg.len, msg.str);
    std::exit(7);
}
static void on_basic(csubstr msg, ryml::ErrorDataBasic const &, void *)
{
    std::printf("BASIC_ERROR %.*s\n", (int)msg.len, msg.str);
    std::exit(8);
}

int main(int argc, char **argv)
{
    ryml::Callbacks cb = ryml::get_callbacks();
    cb.m_error_parse = &on_parse;
    cb.m_error_basic = &on_basic;
    ryml::set_callbacks(cb);
    char buf[256] = {0};
    const char *src = argc > 1 ? argv[1] : "[&a &b &c x]";
    std::size_t len = std::strlen(src);
    std::memcpy(buf, src, len);
    ryml::Tree tree = ryml::parse_in_place(ryml::substr(buf, len));
    std::printf("PARSED nodes=%zu\n", (std::size_t)tree.size());
    return 0;
}

# ida_srclang

Third-party compiler support.

## Constants

- `SRCLANG_C`
- `SRCLANG_CPP`: C++.
- `SRCLANG_OBJC`: Objective-C.
- `SRCLANG_SWIFT`: Swift (not supported yet)
- `SRCLANG_GO`: Golang (not supported yet)

## Functions Overview

- `select_parser_by_name(name: str) -> bool`: Set the parser with the given name as the current parser. Pass nullptr or an empty string to select the default parser.
- `select_parser_by_srclang(lang: srclang_t) -> bool`: Set the parser that supports the given language(s) as the current parser. The selected parser must support all languages specified by the given srclang_t.
- `get_selected_parser_name() -> str`: Get current parser name.
- `set_parser_argv(parser_name: str, argv: str) -> int`: Set the command-line args to use for invocations of the parser with the given name
- `parse_decls_for_srclang(lang: srclang_t, til: til_t, input: str, is_path: bool) -> int`: Parse type declarations in the specified language
- `parse_decls_with_parser_ext(parser_name: str, til: til_t, input: str, hti_flags: int) -> int`: Parse type declarations using the parser with the specified name
- `get_parser_option(parser_name: str, option_name: str) -> str`: Get option for the parser with the specified name
- `set_parser_option(parser_name: str, option_name: str, option_value: str) -> bool`: Set option for the parser with the specified name
- `parse_decls_with_parser(parser_name: str, til: til_t, input: str, is_path: bool) -> int`: Parse type declarations using the parser with the specified name
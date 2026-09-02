from nexus.tools.container import _shell_quote


def test_shell_quote_safe():
    assert _shell_quote("nmap") == "nmap"
    assert _shell_quote("-sV") == "-sV"
    assert _shell_quote("example.com/path") == "example.com/path"


def test_shell_quote_needs_quoting():
    assert _shell_quote("hello world") == "'hello world'"
    assert _shell_quote("") == "''"
    assert _shell_quote("a'b") == "'a'\\''b'"

from canari.scanner import OutputScanner


class Msg:
    def __init__(self, content):
        self.content = content


class Choice:
    def __init__(self, message):
        self.message = message


class OpenAILikeResponse:
    def __init__(self, text):
        self.choices = [Choice(Msg(text))]


def test_extract_openai_like_response():
    result = OpenAILikeResponse("hello world")
    assert OutputScanner._extract_text(result) == "hello world"


def test_extract_openai_like_dict_response():
    result = {"choices": [{"message": {"content": "dict content"}}]}
    assert OutputScanner._extract_text(result) == "dict content"

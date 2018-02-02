from main import _sha256


def test__sha256():
    bs = b'abc'
    print(_sha256(bs))


if __name__ == '__main__':
    test__sha256()

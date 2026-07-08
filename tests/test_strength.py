from analyzer.strength import analyze_password


def test_strong_password():

    result = analyze_password("MyStrongPassword@2026!")

    assert result["score"] >= 80
    assert result["strength"] in ["Strong", "Very Strong"]
    assert result["entropy"] > 80
    assert len(result["weaknesses"]) == 0


def test_weak_password():

    result = analyze_password("123456")

    assert result["score"] < 40
    assert result["strength"] in ["Very Weak", "Weak"]
    assert len(result["weaknesses"]) > 0


def test_empty_password():

    result = analyze_password("")

    assert result["entropy"] == 0
    assert result["score"] == 0


def test_keyboard_pattern():

    result = analyze_password("qwerty123")

    assert result["patterns"]["keyboard"] is True


def test_sequential_pattern():

    result = analyze_password("abc123XYZ")

    assert result["patterns"]["sequential"] is True


def test_repeated_pattern():

    result = analyze_password("AAA111!!!")

    assert result["patterns"]["repeated"] is True


def test_statistics():

    result = analyze_password("Abc123!")

    stats = result["statistics"]

    assert stats["uppercase"] == 1
    assert stats["lowercase"] == 2
    assert stats["numbers"] == 3
    assert stats["symbols"] == 1
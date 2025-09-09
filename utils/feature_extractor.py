def extract_features(url):
    return {
        "length": len(url),
        "has_login": int("login" in url.lower()),
        "has_secure": int("secure" in url.lower()),
        "dots": url.count("."),
        "digits": sum(c.isdigit() for c in url),
        "ends_ru": int(url.endswith(".ru")),
        "ends_cn": int(url.endswith(".cn")),
        "ends_xyz": int(url.endswith(".xyz")),
        "ends_info": int(url.endswith(".info"))
    }
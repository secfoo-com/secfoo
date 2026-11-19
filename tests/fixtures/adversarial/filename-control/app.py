def render_profile(query):
    name = query.get("name", "Guest")
    return "<html><body>Hello " + name + "</body></html>"

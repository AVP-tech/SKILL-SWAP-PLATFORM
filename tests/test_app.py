import pytest


@pytest.fixture(scope="session")
def app_module(tmp_path_factory):
    import skillswap.app as app_module

    db_dir = tmp_path_factory.mktemp("db")
    db_path = db_dir / "test_skill_swap.db"

    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path.as_posix()}",
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
        REMEMBER_COOKIE_SECURE=False,
    )

    return app_module


@pytest.fixture(autouse=True)
def reset_database(app_module):
    with app_module.app.app_context():
        app_module.db.session.remove()
        app_module.db.drop_all()
        app_module.db.create_all()

    yield

    with app_module.app.app_context():
        app_module.db.session.remove()


def create_user(app_module, *, name, email, password="Password123", is_public=True, location="", availability="anytime"):
    with app_module.app.app_context():
        user = app_module.User(
            name=name,
            email=email,
            password=app_module.bcrypt.generate_password_hash(password).decode("utf-8"),
            is_public=is_public,
            location=location,
            availability=availability,
        )
        app_module.db.session.add(user)
        app_module.db.session.commit()
        return user.id


def set_user_skills(app_module, user_id, *, offered=None, wanted=None):
    with app_module.app.app_context():
        if offered:
            app_module.db.session.add(
                app_module.Skill(user_id=user_id, skill_name=offered, type="offered")
            )
        if wanted:
            app_module.db.session.add(
                app_module.Skill(user_id=user_id, skill_name=wanted, type="wanted")
            )
        app_module.db.session.commit()


def login(client, email, password="Password123"):
    return client.post("/api/login", json={"email": email, "password": password})


def test_register_login_and_profile_workflow(app_module):
    client = app_module.app.test_client()

    register_response = client.post(
        "/register",
        data={
            "name": "Nikita",
            "email": "nikita@example.com",
            "password": "Password123",
            "confirm": "Password123",
        },
        follow_redirects=False,
    )
    assert register_response.status_code == 302
    assert register_response.headers["Location"].endswith("/login")

    login_response = login(client, "nikita@example.com")
    assert login_response.status_code == 200
    assert login_response.get_json()["message"] == "Login successful!"

    initial_profile = client.get("/api/get_profile")
    assert initial_profile.status_code == 200
    initial_profile_json = initial_profile.get_json()
    assert initial_profile_json["name"] == "Nikita"
    assert initial_profile_json["skills_offered"] == ""
    assert initial_profile_json["visibility"] == "public"

    update_response = client.post(
        "/api/update_profile",
        json={
            "name": "Nikita Pandey",
            "location": "Pune",
            "skills_offered": "Python",
            "skills_wanted": "Photoshop",
            "availability": "weekends",
            "visibility": "public",
        },
    )
    assert update_response.status_code == 200

    updated_profile = client.get("/api/get_profile").get_json()
    assert updated_profile["name"] == "Nikita Pandey"
    assert updated_profile["location"] == "Pune"
    assert updated_profile["skills_offered"] == "Python"
    assert updated_profile["skills_wanted"] == "Photoshop"
    assert updated_profile["availability"] == "weekends"


def test_browse_filters_and_pagination(app_module):
    current_user_id = create_user(app_module, name="Current User", email="current@example.com")
    set_user_skills(app_module, current_user_id, offered="Guitar", wanted="Excel")

    user1_id = create_user(
        app_module,
        name="Anjali",
        email="anjali@example.com",
        location="Delhi",
        availability="weekends",
    )
    set_user_skills(app_module, user1_id, offered="Python", wanted="Design")

    user2_id = create_user(
        app_module,
        name="Ravi",
        email="ravi@example.com",
        location="Mumbai",
        availability="evenings",
    )
    set_user_skills(app_module, user2_id, offered="Photoshop", wanted="Public Speaking")

    private_user_id = create_user(
        app_module,
        name="Private User",
        email="private@example.com",
        is_public=False,
        location="Delhi",
        availability="anytime",
    )
    set_user_skills(app_module, private_user_id, offered="Excel", wanted="Python")

    client = app_module.app.test_client()
    assert login(client, "current@example.com").status_code == 200

    page_one = client.get("/skills/offered?page=1&per_page=1")
    assert page_one.status_code == 200
    page_one_json = page_one.get_json()
    assert page_one_json["pagination"]["total"] == 2
    assert page_one_json["pagination"]["pages"] == 2
    assert len(page_one_json["items"]) == 1

    python_search = client.get("/skills/offered?q=python")
    assert python_search.status_code == 200
    python_json = python_search.get_json()
    assert python_json["pagination"]["total"] == 1
    assert python_json["items"][0]["name"] == "Anjali"
    assert python_json["items"][0]["skill"] == "Python"

    filtered = client.get("/skills/offered?availability=evenings&location=Mumbai")
    assert filtered.status_code == 200
    filtered_json = filtered.get_json()
    assert filtered_json["pagination"]["total"] == 1
    assert filtered_json["items"][0]["name"] == "Ravi"


def test_swap_request_send_and_accept_flow(app_module):
    requester_id = create_user(
        app_module,
        name="Requester",
        email="requester@example.com",
        location="Pune",
        availability="weekends",
    )
    set_user_skills(app_module, requester_id, offered="Excel", wanted="Photoshop")

    target_id = create_user(
        app_module,
        name="Target",
        email="target@example.com",
        location="Bangalore",
        availability="evenings",
    )
    set_user_skills(app_module, target_id, offered="Photoshop", wanted="Excel")

    requester_client = app_module.app.test_client()
    target_client = app_module.app.test_client()

    assert login(requester_client, "requester@example.com").status_code == 200
    assert login(target_client, "target@example.com").status_code == 200

    create_response = requester_client.post("/swap_request", json={"target_id": target_id})
    assert create_response.status_code == 201
    request_id = create_response.get_json()["request_id"]

    duplicate_response = requester_client.post("/swap_request", json={"target_id": target_id})
    assert duplicate_response.status_code == 409

    target_requests = target_client.get("/api/swap_requests")
    assert target_requests.status_code == 200
    target_requests_json = target_requests.get_json()
    assert len(target_requests_json["received"]) == 1
    assert target_requests_json["received"][0]["status"] == "pending"

    respond_response = target_client.post(f"/respond_swap/{request_id}", json={"status": "accepted"})
    assert respond_response.status_code == 200

    requester_requests = requester_client.get("/api/swap_requests")
    assert requester_requests.status_code == 200
    requester_requests_json = requester_requests.get_json()
    assert len(requester_requests_json["sent"]) == 1
    assert requester_requests_json["sent"][0]["status"] == "accepted"

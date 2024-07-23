#!/usr/bin/env python3
"""Main module"""


import requests


BASE_URL = "http://localhost:5000"


def register_user(email: str, password: str) -> None:
    """Register a new user via the "/users" endpoint"""
    url = f"{BASE_URL}/users"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json()["email"] == email
    print("User registered successfully.")


def log_in_wrong_password(email: str, password: str) -> None:
    """Attempt to log in with an incorrect password via
    the "/sessions" endpoint"""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 400
    assert response.json()["message"] == "wrong password"
    print("Login with wrong password failed as expected.")


def log_in(email: str, password: str) -> str:
    """Log in with the correct credentials via the "/sessions" endpoint"""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert "session_id" in response.json()
    session_id = response.json()["session_id"]
    print("Logged in successfully.")
    return session_id


def profile_unlogged() -> None:
    """Access the profile endpoint without logging in"""
    url = f"{BASE_URL}/profile"
    response = requests.get(url)
    assert response.status_code == 403
    print("Profile access without login failed as expected.")


def profile_logged(session_id: str) -> None:
    """Access the profile endpoint after logging in"""
    url = f"{BASE_URL}/profile"
    headers = {"session_id": session_id}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200
    assert "email" in response.json()
    print("Profile accessed successfully.")


def log_out(session_id: str) -> None:
    """Log out the user by invalidating the session ID"""
    url = f"{BASE_URL}/sessions"
    headers = {"session_id": session_id}
    response = requests.delete(url, headers=headers)
    assert response.status_code == 200
    print("Logged out successfully.")


def reset_password_token(email: str) -> str:
    """Request a reset token for the user's password"""
    url = f"{BASE_URL}/reset_password"
    data = {"email": email}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert "reset_token" in response.json()
    reset_token = response.json()["reset_token"]
    print("Reset password token received.")
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update the user's password using the reset token"""
    url = f"{BASE_URL}/reset_password"
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=data)
    assert response.status_code == 200
    print("Password updated successfully.")


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
    
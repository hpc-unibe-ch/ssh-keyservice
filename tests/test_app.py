import pytest

def test_something(app):
    # use test client or app contextt import mock
    assert app.config["CLIENT_ID"] == "mocked_app_client_id"
    assert app.config["SECRET_KEY"].startswith("mocked_")

def test_home_redirects_if_not_logged_in(client):
    response = client.get("/")
    assert response.status_code == 302  # Redirect to login


#@pytest.fixture
#def client():
#    app.config['TESTING'] = True
#    with app.test_client() as client:
#        with app.app_context():
#            yield client
#
def test_index(client):
    """Test the index page."""
    response = client.get('/')
    assert response.status_code == 302  # Redirect to login if not authenticated

#def test_login(client):
#    """Test the login page."""
#    response = client.get('/login')
#    assert response.status_code == 200
#    assert b'Login' in response.data

def test_logout(client):
    """Test the logout route."""
    response = client.get('/logout')
    assert response.status_code == 302  # Redirect to index after logout

def test_add_key_get(client):
    """Test the add_key route with GET method."""
    response = client.get('/add_key')
    assert response.status_code == 302  # Redirect to login if not authenticated

def test_verify_key_get(client):
    """Test the verify_key route with GET method."""
    response = client.get('/verify_key')
    assert response.status_code == 302  # Redirect to login if not authenticated

def test_delete_key_post(client):
    """Test the delete_key route with POST method."""
    response = client.post('/delete_key', data={'public_key': 'test_key'})
    assert response.status_code == 302  # Redirect to login if not authenticated

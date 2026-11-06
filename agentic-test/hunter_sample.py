"""Small shop API with intentional design flaws, used to exercise the SonarQube Hunter Agent.

Hunter looks for broken access control, business logic and authentication/session flaws. Those are
missing or wrong rules (who may do what, what the server trusts), not tainted data reaching a sink, so
none of them is visible to a single-line pattern matcher.
"""
import hashlib
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    1: {"name": "alice", "role": "customer", "password": "alice-pw", "balance": 100},
    2: {"name": "bob", "role": "customer", "password": "bob-pw", "balance": 100},
    3: {"name": "root", "role": "admin", "password": "root-pw", "balance": 0},
}
ORDERS = {}
COUPONS = {"WELCOME10": {"percent": 10, "used_by": set()}}
SESSIONS = {}


# --- authentication and session -------------------------------------------------------------

def make_token(user_id):
    # predictable: md5 of the user id and the current second, easy to guess for any user
    return hashlib.md5(f"{user_id}{int(time.time())}".encode()).hexdigest()


@app.post("/login")
def login():
    body = request.get_json()
    for user_id, user in USERS.items():
        if user["name"] == body["name"] and user["password"] == body["password"]:
            token = make_token(user_id)
            SESSIONS[token] = user_id  # never expires, never rotated, survives logout
            return jsonify(token=token)
    return jsonify(error="bad credentials"), 401  # no rate limit or lockout, unlimited guessing


@app.post("/logout")
def logout():
    return jsonify(ok=True)  # the token is not removed from SESSIONS, so it stays valid


def current_user_id():
    return SESSIONS.get(request.headers.get("X-Token"))


# --- broken access control ------------------------------------------------------------------

@app.get("/orders/<int:order_id>")
def get_order(order_id):
    if current_user_id() is None:
        return jsonify(error="login required"), 401
    return jsonify(ORDERS[order_id])  # any logged-in user can read any order: no owner check


@app.post("/users/<int:user_id>")
def update_user(user_id):
    if current_user_id() is None:
        return jsonify(error="login required"), 401
    USERS[user_id].update(request.get_json())  # any user can edit any user, including "role": "admin"
    return jsonify(ok=True)


@app.post("/admin/refund/<int:order_id>")
def refund(order_id):
    order = ORDERS[order_id]  # endpoint is reachable by everyone: it never checks the admin role
    USERS[order["user_id"]]["balance"] += order["total"]
    return jsonify(ok=True)


# --- business logic -------------------------------------------------------------------------

@app.post("/orders")
def create_order():
    user_id = current_user_id()
    if user_id is None:
        return jsonify(error="login required"), 401
    body = request.get_json()
    # price and quantity come from the client: a negative quantity or a price of 0 pays nothing,
    # and a negative total credits the buyer
    total = body["unit_price"] * body["quantity"]

    coupon = COUPONS.get(body.get("coupon"))
    if coupon:
        total -= total * coupon["percent"] / 100
        # "used_by" is checked nowhere, so the single-use coupon applies on every order

    order_id = len(ORDERS) + 1
    ORDERS[order_id] = {"user_id": user_id, "total": total}
    USERS[user_id]["balance"] -= total  # no check that the balance covers the total
    return jsonify(order_id=order_id, total=total)


@app.post("/orders/<int:order_id>/cancel")
def cancel_order(order_id):
    user_id = current_user_id()
    order = ORDERS[order_id]
    USERS[user_id]["balance"] += order["total"]  # refunds every time it is called: no state check,
    return jsonify(ok=True)                      # so one order can be cancelled repeatedly for credit

from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from decimal import Decimal
import random
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

print("===== APP1.PY IS RUNNING =====")
print("FILE:", __file__)

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


# =========================================================
# HOME / LOGIN PAGE
# =========================================================

@app.route("/")
def home():

    return render_template("login.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["POST"])
def login():

    account_no = request.form["account_no"].strip()
    pin = request.form["pin"].strip()

    if account_no == "" or pin == "":
        flash("Please enter Account Number and PIN.")
        return redirect(url_for("home"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT account_no,
                   name,
                   mobile,
                   email,
                   pin,
                   balance,
                   status,
                   failed_attempts
            FROM accounts
            WHERE account_no = %s
        """, (account_no,))

        account = cursor.fetchone()

        if account is None:

            flash("Account not found.")
            return redirect(url_for("home"))

        # Account blocked check
        if str(account[6] or "").upper() == "BLOCKED":

            flash("Your account is blocked.")
            return redirect(url_for("home"))

        # Wrong PIN
        if str(account[4]) != pin:

            failed = int(account[7] or 0) + 1

            if failed >= 3:

                cursor.execute("""
                    UPDATE accounts
                    SET failed_attempts = %s,
                        status = 'BLOCKED'
                    WHERE account_no = %s
                """, (failed, account_no))

                conn.commit()

                flash(
                    "Wrong PIN 3 times. Your account has been blocked."
                )

            else:

                cursor.execute("""
                    UPDATE accounts
                    SET failed_attempts = %s
                    WHERE account_no = %s
                """, (failed, account_no))

                conn.commit()

                remaining = 3 - failed

                flash(
                    f"Wrong PIN. Attempts remaining: {remaining}"
                )

            return redirect(url_for("home"))

        # Successful login
        cursor.execute("""
            UPDATE accounts
            SET failed_attempts = 0
            WHERE account_no = %s
        """, (account_no,))

        conn.commit()

        session["account_no"] = account[0]
        session["name"] = account[1]

        return redirect(url_for("dashboard"))

    except mysql.connector.Error as e:

        flash(f"Database Error: {e}")
        return redirect(url_for("home"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# REGISTER PAGE
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":

        return render_template("register.html")

    account_no = request.form["account_no"].strip()
    name = request.form["name"].strip()
    mobile = request.form["mobile"].strip()
    email = request.form["email"].strip()
    pin = request.form["pin"].strip()
    confirm_pin = request.form["confirm_pin"].strip()

    # Empty field validation
    if (
        account_no == ""
        or name == ""
        or mobile == ""
        or email == ""
        or pin == ""
        or confirm_pin == ""
    ):

        flash("Please fill all fields.")
        return redirect(url_for("register"))

    # Account number validation
    if not account_no.isdigit():

        flash("Account Number must contain only numbers.")
        return redirect(url_for("register"))

    # Mobile validation
    if not mobile.isdigit() or len(mobile) != 10:

        flash("Mobile Number must be exactly 10 digits.")
        return redirect(url_for("register"))

    # PIN validation
    if len(pin) != 4 or not pin.isdigit():

        flash("PIN must be exactly 4 digits.")
        return redirect(url_for("register"))

    # Confirm PIN
    if pin != confirm_pin:

        flash("PIN does not match.")
        return redirect(url_for("register"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        # Check account already exists
        cursor.execute("""
            SELECT account_no
            FROM accounts
            WHERE account_no = %s
        """, (account_no,))

        existing = cursor.fetchone()

        if existing:

            flash("Account already exists.")
            return redirect(url_for("register"))

        # Create account
        cursor.execute("""
            INSERT INTO accounts
            (
                account_no,
                name,
                mobile,
                email,
                pin,
                balance,
                status,
                failed_attempts
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            account_no,
            name,
            mobile,
            email,
            pin,
            0,
            "ACTIVE",
            0
        ))

        conn.commit()

        flash(
            "Registration Successful! Your account has been created."
        )

        return redirect(url_for("home"))

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database Error: {e}")

        return redirect(url_for("register"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# FORGOT PIN
# =========================================================

@app.route("/forgot-pin", methods=["GET", "POST"])
def forgot_pin():

    if request.method == "GET":

        return render_template("forgot_pin.html")

    account_no = request.form["account_no"].strip()
    mobile = request.form["mobile"].strip()

    if account_no == "" or mobile == "":

        flash(
            "Please enter Account Number and Mobile Number."
        )

        return redirect(url_for("forgot_pin"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mobile
            FROM accounts
            WHERE account_no = %s
        """, (account_no,))

        account = cursor.fetchone()

        if account is None:

            flash("Account not found.")
            return redirect(url_for("forgot_pin"))

        # Mobile verification
        if str(account[0]) != mobile:

            flash("Mobile number does not match.")
            return redirect(url_for("forgot_pin"))

        # Generate 6 digit OTP
        otp = random.randint(100000, 999999)

        # Store OTP in session
        session["reset_account_no"] = account_no
        session["reset_otp"] = str(otp)

        # OTP expiry - 5 minutes
        session["otp_expiry"] = (
            datetime.now() + timedelta(minutes=5)
        ).isoformat()

        # Demo OTP
        return render_template(
            "verify_otp.html",
            otp=otp
        )

    except mysql.connector.Error as e:

        flash(f"Database Error: {e}")

        return redirect(url_for("forgot_pin"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# VERIFY OTP
# =========================================================

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    entered_otp = request.form["otp"].strip()

    saved_otp = session.get("reset_otp")
    expiry = session.get("otp_expiry")

    if saved_otp is None:

        flash("OTP session expired. Please generate OTP again.")

        return redirect(url_for("forgot_pin"))

    # Check expiry
    if expiry:

        expiry_time = datetime.fromisoformat(expiry)

        if datetime.now() > expiry_time:

            session.pop("reset_otp", None)
            session.pop("otp_expiry", None)

            flash("OTP expired. Please generate a new OTP.")

            return redirect(url_for("forgot_pin"))

    # OTP check
    if entered_otp != str(saved_otp):

        flash("Invalid OTP.")

        return redirect(url_for("forgot_pin"))

    # OTP verified
    session["otp_verified"] = True

    session.pop("reset_otp", None)
    session.pop("otp_expiry", None)

    return redirect(url_for("reset_pin"))


# =========================================================
# RESET PIN
# =========================================================

@app.route("/reset-pin", methods=["GET", "POST"])
def reset_pin():

    if not session.get("otp_verified"):

        flash("Please verify OTP first.")

        return redirect(url_for("forgot_pin"))

    account_no = session.get("reset_account_no")

    if not account_no:

        flash("Invalid password reset session.")

        return redirect(url_for("forgot_pin"))

    if request.method == "GET":

        return render_template("reset_pin.html")

    new_pin = request.form["new_pin"].strip()
    confirm_pin = request.form["confirm_pin"].strip()

    # PIN validation
    if len(new_pin) != 4 or not new_pin.isdigit():

        flash("PIN must be exactly 4 digits.")

        return redirect(url_for("reset_pin"))

    if new_pin != confirm_pin:

        flash("PIN does not match.")

        return redirect(url_for("reset_pin"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        # Update PIN
        cursor.execute("""
            UPDATE accounts
            SET pin = %s,
                failed_attempts = 0,
                status = 'ACTIVE'
            WHERE account_no = %s
        """, (
            new_pin,
            account_no
        ))

        conn.commit()

        # Clear reset session
        session.pop("reset_account_no", None)
        session.pop("otp_verified", None)

        flash(
            "PIN changed successfully. Please login with your new PIN."
        )

        return redirect(url_for("home"))

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database Error: {e}")

        return redirect(url_for("reset_pin"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "account_no" not in session:

        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        name=session["name"],
        account_no=session["account_no"]
    )


# =========================================================
# CHECK BALANCE
# =========================================================

@app.route("/balance")
def balance():

    if "account_no" not in session:

        return redirect(url_for("home"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT balance
            FROM accounts
            WHERE account_no = %s
        """, (session["account_no"],))

        result = cursor.fetchone()

        if result is None:

            flash("Account not found.")

            return redirect(url_for("dashboard"))

        return render_template(
            "balance.html",
            balance=result[0]
        )

    except mysql.connector.Error as e:

        flash(f"Database Error: {e}")

        return redirect(url_for("dashboard"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# DEPOSIT
# =========================================================

@app.route("/deposit", methods=["GET", "POST"])
def deposit():

    if "account_no" not in session:

        return redirect(url_for("home"))

    if request.method == "GET":

        return render_template("deposit.html")

    amount_text = request.form["amount"].strip()

    try:

        amount = Decimal(amount_text)

        if amount <= 0:

            flash("Enter a valid amount.")

            return redirect(url_for("deposit"))

    except:

        flash("Please enter a valid amount.")

        return redirect(url_for("deposit"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT balance
            FROM accounts
            WHERE account_no = %s
        """, (session["account_no"],))

        result = cursor.fetchone()

        if result is None:

            flash("Account not found.")

            return redirect(url_for("dashboard"))

        previous_balance = Decimal(str(result[0]))

        new_balance = previous_balance + amount

        cursor.execute("""
            UPDATE accounts
            SET balance = %s
            WHERE account_no = %s
        """, (
            new_balance,
            session["account_no"]
        ))

        cursor.execute("""
            INSERT INTO transactions
            (
                account_no,
                transaction_type,
                amount,
                previous_balance,
                new_balance
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session["account_no"],
            "DEPOSIT",
            amount,
            previous_balance,
            new_balance
        ))

        conn.commit()

        flash(
            f"₹{amount:.2f} deposited successfully."
        )

        return redirect(url_for("dashboard"))

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database Error: {e}")

        return redirect(url_for("deposit"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# WITHDRAW
# =========================================================

@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():

    if "account_no" not in session:

        return redirect(url_for("home"))

    if request.method == "GET":

        return render_template("withdraw.html")

    amount_text = request.form["amount"].strip()

    try:

        amount = Decimal(amount_text)

        if amount <= 0:

            flash("Enter a valid amount.")

            return redirect(url_for("withdraw"))

    except:

        flash("Please enter a valid amount.")

        return redirect(url_for("withdraw"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT balance
            FROM accounts
            WHERE account_no = %s
        """, (session["account_no"],))

        result = cursor.fetchone()

        if result is None:

            flash("Account not found.")

            return redirect(url_for("dashboard"))

        previous_balance = Decimal(str(result[0]))

        if amount > previous_balance:

            flash("Insufficient balance.")

            return redirect(url_for("withdraw"))

        new_balance = previous_balance - amount

        cursor.execute("""
            UPDATE accounts
            SET balance = %s
            WHERE account_no = %s
        """, (
            new_balance,
            session["account_no"]
        ))

        cursor.execute("""
            INSERT INTO transactions
            (
                account_no,
                transaction_type,
                amount,
                previous_balance,
                new_balance
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            session["account_no"],
            "WITHDRAW",
            amount,
            previous_balance,
            new_balance
        ))

        conn.commit()

        flash(
            f"₹{amount:.2f} withdrawn successfully."
        )

        return redirect(url_for("dashboard"))

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database Error: {e}")

        return redirect(url_for("withdraw"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# MINI STATEMENT
# =========================================================

@app.route("/statement")
def statement():

    if "account_no" not in session:

        return redirect(url_for("home"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT transaction_type,
                   amount,
                   previous_balance,
                   new_balance,
                   transaction_date
            FROM transactions
            WHERE account_no = %s
            ORDER BY transaction_date DESC
            LIMIT 10
        """, (session["account_no"],))

        transactions = cursor.fetchall()

        return render_template(
            "statement.html",
            transactions=transactions
        )

    except mysql.connector.Error as e:

        flash(f"Database Error: {e}")

        return redirect(url_for("dashboard"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# CHANGE PIN
# =========================================================

@app.route("/change-pin", methods=["GET", "POST"])
def change_pin():

    if "account_no" not in session:

        return redirect(url_for("home"))

    if request.method == "GET":

        return render_template("change_pin.html")

    current_pin = request.form["current_pin"].strip()
    new_pin = request.form["new_pin"].strip()
    confirm_pin = request.form["confirm_pin"].strip()

    if (
        current_pin == ""
        or new_pin == ""
        or confirm_pin == ""
    ):

        flash("Please fill all fields.")

        return redirect(url_for("change_pin"))

    if len(new_pin) != 4 or not new_pin.isdigit():

        flash("PIN must be exactly 4 digits.")

        return redirect(url_for("change_pin"))

    if new_pin != confirm_pin:

        flash("New PIN and Confirm PIN do not match.")

        return redirect(url_for("change_pin"))

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT pin
            FROM accounts
            WHERE account_no = %s
        """, (session["account_no"],))

        result = cursor.fetchone()

        if result is None:

            flash("Account not found.")

            return redirect(url_for("dashboard"))

        if str(result[0]) != current_pin:

            flash("Current PIN is incorrect.")

            return redirect(url_for("change_pin"))

        cursor.execute("""
            UPDATE accounts
            SET pin = %s,
                failed_attempts = 0,
                status = 'ACTIVE'
            WHERE account_no = %s
        """, (
            new_pin,
            session["account_no"]
        ))

        conn.commit()

        flash("PIN changed successfully.")

        return redirect(url_for("dashboard"))

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        flash(f"Database Error: {e}")

        return redirect(url_for("change_pin"))

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("home"))


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000)
from flask import Flask, render_template, request, redirect, session, url_for, flash, make_response
import requests
import os
from flask_session import Session  # Improved session handling

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default_secret_key")
app.config["SESSION_TYPE"] = "filesystem"  # Can use "redis" for better performance
app.config["SESSION_PERMANENT"] = False  # Session expires when the browser closes
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents JavaScript access (security)
app.config["SESSION_COOKIE_SECURE"] = True  # Requires HTTPS (set to False for local dev)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protects against CSRF attacks


Session(app)


def fetch_id_token():
    api_url_firebase = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key=AIzaSyBunadFCCmB9O-0bCB2GOYgWuFpKsso-zs"
    
    firebase_payload = {"returnSecureToken": True}
    firebase_headers = {
        "Content-Type": "application/json",
        "User-Agent": "FirebaseAuth.iOS/9.5.0 com.IITBombay.EFAS/3.4.22 iPhone/17.6 hw/iPhone14_5",
        "X-Client-Version": "iOS/FirebaseSDK/9.5.0/FirebaseCore-iOS",
        "X-Ios-Bundle-Identifier": "com.IITBombay.EFAS",
        "X-Firebase-Gmpid": "1:847012183475:ios:497dee825264202f"
    }
    
    try:
        response = requests.post(api_url_firebase, json=firebase_payload, headers=firebase_headers)
        response_data = response.json()
        return response_data.get("idToken")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching ID token: {str(e)}")
        return None
    

def safeapp_login(email, passcode, id_token):
    api_url_safeapp = "https://safeapp.iitb.ac.in/api/account/login/"
    safeapp_payload = {
        "email_id": email,
        "passcode": passcode,
        "anonymous_token": id_token
    }
    safeapp_headers = {
        "Content-Type": "application/json",
        "User-Agent": "SAFE/3.4.22 (com.IITBombay.EFAS; build:1.1; iOS 17.6.0) Alamofire/4.9.1",
        "Safeversion": "i3.4.22"
    }
    
    try:
        response = requests.post(api_url_safeapp, json=safeapp_payload, headers=safeapp_headers)
        response_data = response.json()
        return response_data.get("token")
    except requests.exceptions.RequestException as e:
        print(f"Error during SAFE app login: {str(e)}")
        return None


def get_course_details(auth_token):
    api_url_courses = "https://safeapp.iitb.ac.in/api/course/"
    headers = {
        "Content-Type": "application/json",
        "Safeversion": "i3.4.22",
        "Accept": "*/*",
        "Authorization": f"Token {auth_token}",
        "Accept-Language": "en-IN;q=1.0",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "SAFE/3.4.22 (com.IITBombay.EFAS; build:1.1; iOS 17.6.0) Alamofire/4.9.1",
        "Devicemodel": "iPhone14,5",
        "Osversion": "17.6",
        "Connection": "close"
    }

    try:
        response = requests.get(api_url_courses, headers=headers)
        response.raise_for_status()
        
        try:
            data = response.json()
        except ValueError:
            return {"error": "Invalid JSON response from API"}

        if "result" not in data:
            return {"error": "Unexpected API response format"}

        course_details = [
            {
                "name": course.get("name"),
                "code": course.get("code"),
                "description": course.get("description"),
                "attendance_image": course.get("attendance_image"),
                "detect_attendancewindow": course.get("detect_attendancewindow")
            }
            for course in data.get("result", [])
        ]

        return course_details

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
            return {"error": "Unauthorized: Invalid auth token"}
        return {"error": f"HTTP error: {http_err}"}
    
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Request error: {req_err}"}

def get_attendance_list(auth_token, course_code, start_date, end_date):
    
    api_url = "https://safeapp.iitb.ac.in/api/attendance/attendance_list/"
    
    # Headers for the request
    headers = {
        "Content-Type": "application/json",
        "Safeversion": "i3.4.22",
        "Accept": "*/*",
        "Authorization": f"Token {auth_token}",
        "Accept-Language": "en-IN;q=1.0",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "SAFE/3.4.22 (com.IITBombay.EFAS; build:1.1; iOS 17.6.0) Alamofire/4.9.1",
        "Devicemodel": "iPhone14,5",
        "Osversion": "17.6",
        "Connection": "close"
    }
    
    # Payload for the POST request
    payload = {
        "start_date": start_date,
        "course": course_code,
        "end_date": end_date
    }

    try:
        # Send the POST request
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()  # Return JSON response if successful
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}  # Return error message in case of failure

#Processing the Attendance list data into readable format / prints directly
def process_attendance_response(response_data):
    """
    Processes and displays detailed attendance information from the API response.
    """
    if "attendance_array" not in response_data or not response_data["attendance_array"]:
        print("No attendance records found.")
        return

    attendance_records = response_data["attendance_array"]
    user_id = response_data.get("user_id", "Unknown")

    print(f"User ID: {user_id}\nAttendance Records:")
    for record in attendance_records:
        date = record.get("date", "N/A")
        time = record.get("time", "N/A")
        state = record.get("state", "N/A")
        failure_reasons = record.get("failure_reasons", [])
        face_surety = record.get("face_surety", "N/A")
        flags = record.get("flags", [])
        manually_marked = record.get("manually_marked", "N/A")
        slot = record.get("slot", "N/A")

        print(f"  Date: {date}")
        print(f"  Time: {time}")
        print(f"  State: {state}")
        if failure_reasons:
            print(f"  Failure Reasons: {', '.join(failure_reasons)}")
        
        # Handle face_surety formatting safely
        try:
            face_surety_value = float(face_surety)
            print(f"  Face Surety: {face_surety_value:.2f}%")
        except (ValueError, TypeError):
            print(f"  Face Surety: {face_surety}")

        if flags:
            print(f"  Flags: {', '.join(flags)}")
        print(f"  Manually Marked: {'Yes' if manually_marked else 'No'}")
        print(f"  Slot: {slot}\n")

from datetime import datetime

def get_current_date():
    # Get the current date
    current_date = datetime.now()

    # Format the current date in "DD-MM-YYYY" format
    formatted_date = current_date.strftime("%d-%m-%Y")
    
    return formatted_date



@app.route("/courses")
def courses():
    auth_token = session.get("auth_token")  # Ensure user is logged in
    if not auth_token:
        flash("You must be logged in to view courses.", "warning")
        return redirect(url_for("login"))

    course_data = get_course_details(auth_token)
    
    if "error" in course_data:
        flash(course_data["error"], "danger")
        return redirect(url_for("dashboard"))

    return render_template("courses.html", courses=course_data)
                           

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        id_token = fetch_id_token()
        if not id_token:
            flash("Error fetching ID token. Please try again.", "danger")
            return redirect(url_for("login"))
        
        auth_token = safeapp_login(email, password, id_token)
        if not auth_token:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for("login"))
        
        # Store auth_token as a secure session cookie
        session["auth_token"] = auth_token
        print(auth_token)
        # Create a secure cookie
        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie("auth_token", auth_token, httponly=True, secure=True, samesite="Lax")
        
        flash("Login successful!", "success")
        return response  # Return response with cookie set
    
    return render_template("login.html")


def get_current_date():
    current_date = datetime.now()
    return current_date.strftime("%d-%m-%Y")



def get_current_time_formatted():
    """
    Returns the current time in the format: YYYY-MM-DDTHH:MM:SS.sss+ZZZZ
    """
    current_time = datetime.now().astimezone()  # Get current time with timezone
    return current_time.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    

import base64
import re

def convert_image_to_base64(image_file):
    """
    Converts an uploaded image file to a base64-encoded string and replaces '/' with '\/' using regex.
    
    :param image_file: FileStorage object from Flask request.files
    :return: Base64 encoded string with '/' replaced by '\/'
    """
    try:
        image_binary = image_file.read()  # Read file as binary
        encoded_image = base64.b64encode(image_binary).decode("utf-8")  # Encode to base64 string
        encoded_image = re.sub(r'/', r'\/', encoded_image)  # Replace '/' with '\/' using regex
        return encoded_image
    except Exception as e:
        print(f"Error encoding image: {e}")
        return None

def send_attendance(auth_token, course_code, image_path, mac_address, imei, wifi_ssid, wifi_bssid, ip_address, formatted_time, attendance_image):
    
    image_binary = image_path.read()  # Read file as binary
    encoded_image = base64.b64encode(image_binary).decode("utf-8")  # Encode to base64 string
    encoded_image = re.sub(r'/', r'\/', encoded_image)

    if attendance_image == False:
    
        data = {
            "seconds_since_mark": 0,
            "client_time": f"{formatted_time}", 
            "app_version": "i3.4.22",
            "mac_address": mac_address,
            "wifi_signature": {},
            "course": course_code,
            "ip_address": ip_address,
            "wifi_details": {
                "SSID": wifi_ssid,
                "BSSID": wifi_bssid
            },
            "signal_strength_signature": {},
            "IMEI": imei
        }
    elif attendance_image == True:
        data = {
            "seconds_since_mark": 0,
            "client_time": f"{formatted_time}", 
            "app_version": "i3.4.22",
            "mac_address": mac_address,
            "wifi_signature": {},
            "attendance_image_file":encoded_image,
            "course": course_code,
            "ip_address": ip_address,
            "wifi_details": {
                "SSID": wifi_ssid,
                "BSSID": wifi_bssid
            },
            "signal_strength_signature": {},
            "IMEI": imei
        }
    # If attendance_image is True, include the image in the data

    
    # API URL for attendance
    api_url = "https://safeapp.iitb.ac.in/api/attendance/"
    
    # Headers for the request
    headers = {
        "Content-Type": "application/json",
        "Safeversion": "i3.4.22",
        "Accept": "*/*",
        "Authorization": f"Token {auth_token}",
        "Accept-Language": "en-IN;q=1.0",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "SAFE/3.4.22 (com.IITBombay.EFAS; build:1.1; iOS 17.6.0) Alamofire/4.9.1",
        "Devicemodel": "iPhone14,5",
        "Osversion": "17.6",
        "Connection": "close"
    }
   
    print(data)
    try:
        # Send the POST request to the server
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()  # Return JSON response if successful
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}  # Return error message in case of failure


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    auth_token = request.cookies.get("auth_token")  # Retrieve from cookie
    if not auth_token:
        flash("You must be logged in.", "warning")
        return redirect(url_for("login"))
    
    # Fetch course data
    course_data = get_course_details(auth_token)
    if "error" in course_data:
        flash(course_data["error"], "danger")
        return redirect(url_for("login"))

    # Set start_date to a fixed value and end_date to the current date
    start_date = "01-01-2018"
    end_date = get_current_date()

    # Handle attendance retrieval if form is submitted
    if request.method == "POST":
        course_code = request.form["course_code"]
        
        # Use the dynamically set start_date and end_date
        attendance_data = get_attendance_list(auth_token, course_code, start_date, end_date)
        
        if "error" in attendance_data:
            flash("Error fetching attendance data.", "danger")
        else:
            flash("Attendance data retrieved successfully.", "success")

        return render_template("dashboard.html", courses=course_data, attendance=attendance_data)

    return render_template("dashboard.html", courses=course_data)


@app.route("/mark_attendance", methods=["GET", "POST"])
def mark_attendance():
    auth_token = request.cookies.get("auth_token")  # Retrieve from cookies
    if not auth_token:
        flash("You must be logged in.", "warning")
        return redirect(url_for("login"))

    courses = get_course_details(auth_token)  # Fetch available courses
    if not courses or "error" in courses:
        flash("Error fetching courses. Please try again.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        course_code = request.form["course_code"]
        mac_address = request.form["mac_address"]
        imei = request.form["imei"]
        wifi_ssid = request.form["wifi_ssid"]
        wifi_bssid = request.form["wifi_bssid"]
        ip_address = request.form["ip_address"]
        formatted_time = get_current_time_formatted()

        # Find if the course requires an attendance image
        selected_course = next((c for c in courses if c["code"] == course_code), None)
        image_required = selected_course and selected_course.get("attendance_image", False)

        # Handle image upload if required
        image_path = None
        if image_required and "attendance_image" in request.files:
            image_file = request.files["attendance_image"]
            if image_file.filename:
                image_path = image_file
        
        # Send attendance request
        response = send_attendance(
            auth_token, course_code, image_path, mac_address, imei, wifi_ssid, wifi_bssid, ip_address, formatted_time, image_required
        )

        if "error" in response:
            flash(f"Error: {response['error']}", "danger")
        else:
            flash("Attendance marked successfully!", "success")

        return redirect(url_for("dashboard"))

    return render_template("mark_attendance.html", courses=courses)

@app.route("/logout")
def logout():
    session.pop("auth_token", None)  # Remove from session
    response = make_response(redirect(url_for("login")))
    response.set_cookie("auth_token", "", expires=0)  # Clear cookie
    flash("You have been logged out.", "info")
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


import streamlit as st
import google.generativeai as genai
import datetime
import time
import os
import hashlib
import sqlite3
import schedule
import threading
import logging
import pandas as pd
import json  # Import json
from contextlib import contextmanager
from st_aggrid import AgGrid, GridOptionsBuilder
from streamlit_option_menu import option_menu
from PIL import Image
import plotly.express as px

# Page Configuration
st.set_page_config(page_title="EduAssist - Your Learning Companion", layout="wide")

# Custom CSS for a more futuristic look
st.markdown(
    """
    <style>
        body {
            color: #ffffff; /* Light text color */
            background-color: #1e293b; /* Dark background */
        }

        .stApp {
            background-color: #1e293b;
        }

        .stButton>button {
            color: #ffffff;
            background-color: #3b82f6;
            border: none;
            border-radius: 5px;
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
        }

        .stTextInput>div>div>input {
            color: #ffffff;
            background-color: #334155;
            border: 1px solid #475569;
        }

        .stTextArea>div>div>textarea {
            color: #ffffff;
            background-color: #334155;
            border: 1px solid #475569;
        }

        .stSelectbox>div>div>div {
            color: #ffffff;
            background-color: #334155;
            border: 1px solid #475569;
        }

        /* Style the sidebar */
        [data-testid="stSidebar"] {
            background-color: #0f172a;
            color: #ffffff;
        }

        [data-testid="stSidebar"] a {
            color: #ffffff;
        }
         /* Style the main content area */
        [data-testid="stAppViewContainer"] {
            background-color: #1e293b;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# === Database Initialization and Utility Functions ===
@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = None
    try:
        conn = sqlite3.connect('data.db')
        yield conn
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def create_usertable():
    """Creates the user table if it doesn't exist."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS userstable (username TEXT PRIMARY KEY, password TEXT)')
            conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error creating user table: {e}")

def add_userdata(username, password):
    """Adds user data to the user table."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO userstable (username, password) VALUES (?,?)', (username, password))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        st.error("Username already exists. Please choose a different username.")
        return False
    except sqlite3.Error as e:
        st.error(f"Error adding user: {e}")
        return False

def login_user(username, password):
    """Logs in a user if credentials match."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM userstable WHERE username =? AND password = ?', (username, password))
            data = c.fetchall()
        return data
    except sqlite3.Error as e:
        st.error(f"Error during login: {e}")
        return None

def view_all_users():
    """Retrieves all users from the database (for admin purposes)."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM userstable')
            data = c.fetchall()
        return data
    except sqlite3.Error as e:
        st.error(f"Error retrieving user data: {e}")
        return None

def make_hashes(password):
	return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password,hashed_text):
	if make_hashes(password) == hashed_text:
		return hashed_text
	return False

# === Reminder System Functions ===
def create_reminders_table():
    """Creates the reminders table if it doesn't exist."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS reminders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    task TEXT,
                    reminder_datetime TEXT,
                    notes TEXT,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')
            conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error creating reminders table: {e}")

def add_reminder(username, task, reminder_datetime, notes):
    """Adds a new reminder to the database."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO reminders (username, task, reminder_datetime, notes)
                VALUES (?, ?, ?, ?)
            ''', (username, task, reminder_datetime, notes))
            conn.commit()

            log_reminder(username, task, reminder_datetime, "set") # Log reminder creation

            return True
    except sqlite3.Error as e:
            st.error(f"Error adding reminder: {e}")
            return False

def get_reminders(username):
    """Retrieves all reminders for a given user."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, task, reminder_datetime, notes FROM reminders WHERE username = ?', (username,))
            reminders = c.fetchall()
        return reminders
    except sqlite3.Error as e:
        st.error(f"Error retrieving reminders: {e}")
        return []

def delete_reminder(reminder_id):
    """Deletes a reminder by its ID."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            #Get task detail to log
            c.execute('SELECT username, task, reminder_datetime FROM reminders WHERE id = ?', (reminder_id,))
            reminder_details = c.fetchone()

            c.execute('DELETE FROM reminders WHERE id = ?', (reminder_id,))
            conn.commit()

            if reminder_details:
                 username, task, reminder_datetime = reminder_details
                 log_reminder(username, task, reminder_datetime, "deleted") #Log reminder deletion
            return True
    except sqlite3.Error as e:
            st.error(f"Error deleting reminder: {e}")
            return False

# === Gemini Integration ===
def get_gemini_response(prompt):
    """Gets a response from the Gemini model."""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        st.error(f"Error getting response from Gemini: {e}")
        return None

# === Logging and Analytics Functions ===
def create_activity_tables():
    """Creates the activity logging tables if they don't exist."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            c.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    activity_type TEXT,
                    activity_details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS question_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    question TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS resources_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    topic TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS studyplan_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    goal TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS reminder_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    task TEXT,
                    reminder_datetime TEXT,
                    status TEXT, -- "completed", "missed", "deleted"
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES userstable(username)
                )
            ''')

            conn.commit()

    except sqlite3.Error as e:
        st.error(f"Error creating activity tables: {e}")

def log_activity(username, activity_type, activity_details):
    """Logs user activity to the database."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO user_activity (username, activity_type, activity_details)
                VALUES (?, ?, ?)
            ''', (username, activity_type, json.dumps(activity_details)))  # Store details as JSON
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error logging activity: {e}")

def log_question(username, question):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO question_log (username, question)
                VALUES (?, ?)
            ''', (username, question))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error logging question: {e}")

def log_resource(username, topic):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO resources_log (username, topic)
                VALUES (?, ?)
            ''', (username, topic))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error logging resource: {e}")

def log_studyplan(username, goal):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO studyplan_log (username, goal)
                VALUES (?, ?)
            ''', (username, goal))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error logging studyplan: {e}")

def log_reminder(username, task, reminder_datetime, status):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO reminder_log (username, task, reminder_datetime, status)
                VALUES (?, ?, ?, ?)
            ''', (username, task, reminder_datetime, status))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error logging reminder: {e}")

def get_user_activity_data(username):
    """Retrieves user activity data from the database."""
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query(f"SELECT * FROM user_activity WHERE username = '{username}'", conn)
        return df
    except sqlite3.Error as e:
        st.error(f"Error retrieving user activity data: {e}")
        return pd.DataFrame()

def analyze_user_data(username):
    """Performs analysis on user activity data."""
    # Use individual log tables instead of user_activity
    try:
        with get_db_connection() as conn:
            question_df = pd.read_sql_query(f"SELECT * FROM question_log WHERE username = '{username}'", conn)
            resources_df = pd.read_sql_query(f"SELECT * FROM resources_log WHERE username = '{username}'", conn)
            studyplan_df = pd.read_sql_query(f"SELECT * FROM studyplan_log WHERE username = '{username}'", conn)
            reminder_df = pd.read_sql_query(f"SELECT * FROM reminder_log WHERE username = '{username}'", conn)

    except sqlite3.Error as e:
        st.error(f"Error retrieving data for analysis: {e}")
        return None

    analysis_results = {}

    # Question Analysis
    if not question_df.empty:
        analysis_results['question_count'] = len(question_df)
        analysis_results['recent_questions'] = question_df.sort_values(by='timestamp', ascending=False).head(5)
    else:
        analysis_results['question_count'] = 0
        analysis_results['recent_questions'] = pd.DataFrame()

    # Resources Analysis
    if not resources_df.empty:
        analysis_results['resource_count'] = len(resources_df)
        analysis_results['recent_resources'] = resources_df.sort_values(by='timestamp', ascending=False).head(5)
    else:
        analysis_results['resource_count'] = 0
        analysis_results['recent_resources'] = pd.DataFrame()

    # Study Plan Analysis
    if not studyplan_df.empty:
        analysis_results['studyplan_count'] = len(studyplan_df)
        analysis_results['recent_studyplans'] = studyplan_df.sort_values(by='timestamp', ascending=False).head(5)
    else:
        analysis_results['studyplan_count'] = 0
        analysis_results['recent_studyplans'] = pd.DataFrame()

    # Reminder Analysis
    if not reminder_df.empty:
        analysis_results['reminder_count'] = len(reminder_df)
        analysis_results['completed_reminders'] = len(reminder_df[reminder_df['status'] == 'completed'])
        analysis_results['missed_reminders'] = len(reminder_df[reminder_df['status'] == 'missed'])
        analysis_results['recent_reminders'] = reminder_df.sort_values(by='timestamp', ascending=False).head(5)

    else:
        analysis_results['reminder_count'] = 0
        analysis_results['completed_reminders'] = 0
        analysis_results['missed_reminders'] = 0
        analysis_results['recent_reminders'] = pd.DataFrame()

    return analysis_results

def display_user_analysis(username):
    """Displays user analysis results using Streamlit."""
    analysis_results = analyze_user_data(username)

    if analysis_results is None:
        st.info("Error retrieving activity data.")
        return

    if not any(isinstance(analysis_results[key], int) or (isinstance(analysis_results[key], pd.DataFrame) and not analysis_results[key].empty) for key in analysis_results): #Check if all analysis results are empty
        st.info("No activity data available for this user.")
        return

    st.header("Your Learning Analytics")

    # Questions Analysis
    st.subheader("Questions Asked")
    st.write(f"Total questions asked: {analysis_results['question_count']}")
    if not analysis_results['recent_questions'].empty:
        st.dataframe(analysis_results['recent_questions'][['question', 'timestamp']])

    # Resources Analysis
    st.subheader("Resources Requested")
    st.write(f"Total resources requested: {analysis_results['resource_count']}")
    if not analysis_results['recent_resources'].empty:
        st.dataframe(analysis_results['recent_resources'][['topic', 'timestamp']])

    # Study Plans Analysis
    st.subheader("Study Plans Generated")
    st.write(f"Total study plans generated: {analysis_results['studyplan_count']}")
    if not analysis_results['recent_studyplans'].empty:
        st.dataframe(analysis_results['recent_studyplans'][['goal', 'timestamp']])

    # Reminders Analysis
    st.subheader("Reminders Performance")
    st.write(f"Total reminders set: {analysis_results['reminder_count']}")
    st.write(f"Completed reminders: {analysis_results['completed_reminders']}")
    st.write(f"Missed reminders: {analysis_results['missed_reminders']}")
    if not analysis_results['recent_reminders'].empty:
        st.dataframe(analysis_results['recent_reminders'][['task', 'reminder_datetime', 'status']])

    # Create a bar chart for reminder statistics
    reminder_stats = pd.DataFrame({
        'Status': ['Completed', 'Missed'],
        'Count': [analysis_results['completed_reminders'], analysis_results['missed_reminders']]
    })

    fig = px.bar(reminder_stats, x='Status', y='Count', title='Reminder Statistics')
    st.plotly_chart(fig)

# === Page Functions ===
def login_page():
    """Login page UI."""
    st.title("Welcome to EduAssist")
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login"):
            create_usertable()
            hashed_pswd = make_hashes(password)
            result = login_user(username, check_hashes(password,hashed_pswd))

            if result:
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.success(f"Logged In as {username}")
                st.rerun()
            else:
                st.warning("Incorrect Username/Password")

    with col2:
        if st.button("Sign Up"):
            st.session_state['page'] = 'signup'
            st.rerun()

def signup_page():
    """Sign-up Page UI"""
    st.title("Create an Account")
    new_user = st.text_input("New Username")
    new_password = st.text_input("New Password", type='password')

    if st.button("Signup"):
        create_usertable()
        hashed_new_password = make_hashes(new_password)
        if add_userdata(new_user, hashed_new_password):
            st.success("Account created successfully. Please log in.")
            st.session_state['page'] = 'login'
            st.rerun()

def academic_assistance_page():
    """Academic Assistance UI."""
    st.title("📚 Academic Assistance")
    option = st.selectbox("Choose a service", ["Ask a Subject Question", "Get Study Resources", "Academic Planning"])

    if option == "Ask a Subject Question":
        question = st.text_input("Enter your academic question:")
        if st.button("Get Answer"):
            if question:
                with st.spinner("Thinking..."):
                    answer = get_gemini_response(question)
                    if answer:
                        st.success("Answer:")
                        st.markdown(answer)
                        log_activity(st.session_state['username'], 'question', {'question': question, 'answer': answer})
                        log_question(st.session_state['username'], question) # Log question
            else:
                st.warning("Please enter a question.")

    elif option == "Get Study Resources":
        topic = st.text_input("Enter topic or subject (e.g. Algebra, Python basics):")
        if st.button("Suggest Resources"):
            if topic:
                prompt = f"Suggest study resources (YouTube, books, articles, PDFs) for the topic: {topic}"
                resources = get_gemini_response(prompt)
                if resources:
                    st.success("Resources:")
                    st.markdown(resources)
                    log_activity(st.session_state['username'], 'resource', {'topic': topic, 'resources': resources})
                    log_resource(st.session_state['username'], topic) # Log resource request

            else:
                st.warning("Please enter a topic.")

    elif option == "Academic Planning":
        goal = st.text_input("Enter your academic goal (e.g. Prepare Python in 10 days):")
        if st.button("Generate Study Plan"):
            if goal:
                prompt = f"Create a personalized, realistic study plan for this academic goal: {goal}"
                plan = get_gemini_response(prompt)
                if plan:
                    st.success("Study Plan:")
                    st.markdown(plan)
                    log_activity(st.session_state['username'], 'study_plan', {'goal': goal, 'plan': plan})
                    log_studyplan(st.session_state['username'], goal) # Log study plan generation

            else:
                st.warning("Please enter a goal.")

def reminder_management_page():
    """Reminder Management UI."""
    st.title("⏰ Reminder Management")
    st.subheader("Manage Study Reminders")
    create_reminders_table()  # Make sure the table exists

    task = st.text_input("Task/Topic to Study:")
    reminder_time = st.time_input("Reminder Time:")
    reminder_date = st.date_input("Reminder Date:")
    notes = st.text_area("Notes (Optional):", height=100)

    if st.button("Set Reminder"):
        if task:
            reminder_datetime = datetime.datetime.combine(reminder_date, reminder_time).strftime('%Y-%m-%d %H:%M')
            if add_reminder(st.session_state['username'], task, reminder_datetime, notes):
                st.success(f"Reminder set for: {task} on {reminder_datetime}")
            else:
                st.error("Failed to set reminder.")
        else:
            st.warning("Please enter a task.")

    # Display Reminders using AgGrid
    reminders = get_reminders(st.session_state['username'])
    if reminders:
        df = pd.DataFrame(reminders, columns=["ID", "Task", "Reminder Time", "Notes"])
        gb = GridOptionsBuilder.from_dataframe(df)
        gb.configure_selection('single', use_checkbox=False)  # Enable single row selection
        gb.configure_column("ID",  width=50)
        gb.configure_column("Task", flex=2)
        gb.configure_column("Reminder Time", flex=2)
        gb.configure_column("Notes", flex=3)
        gridOptions = gb.build()

        grid_response = AgGrid (
            df,
            gridOptions=gridOptions,
            data_return_mode='AS_INPUT',
            update_mode='MODEL_CHANGED',
             fit = "size",
            allow_unsafe_jscode=True, #Set it to True to allow jsfunction to be injected
            enable_enterprise_modules = True
        )

        selected = grid_response['selected_rows']
        if selected:
            selected_id = selected[0]['ID']  # Get the ID of the selected reminder

            if st.button("Delete Selected Reminder"):
                if delete_reminder(selected_id):
                    st.success("Reminder deleted successfully.")
                    st.rerun()
                else:
                    st.error("Failed to delete reminder.")
    else:
        st.info("No reminders set yet.")

def account_settings_page():
    """Account Settings UI."""
    st.title("⚙️ Account Settings")
    st.subheader("User Details")
    user_result = view_all_users()
    if user_result:
        clean_db = pd.DataFrame(user_result,columns=["Username","Password"])
        st.dataframe(clean_db)
    else:
        st.info("Could not retrieve user details.")

# === Background Tasking for Reminders (Simplified Example) ===
def check_and_trigger_reminders():
    """Checks for reminders and displays notifications (simplified)."""
    while True:
        now = datetime.datetime.now()
        current_time = now.strftime('%Y-%m-%d %H:%M')

        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT id, task FROM reminders WHERE reminder_datetime = ?', (current_time,))
                due_reminders = c.fetchall()

                for reminder_id, task in due_reminders:
                    st.toast(f"Reminder: {task}", icon='⏰')  # Use st.toast for non-blocking notification

                    #Log as completed if the user saw the toast and didn't delete it
                    c.execute('SELECT username, task, reminder_datetime FROM reminders WHERE id = ?', (reminder_id,))
                    reminder_details = c.fetchone()
                    if reminder_details:
                        username, task, reminder_datetime = reminder_details
                        log_reminder(username, task, reminder_datetime, "completed")

                    delete_reminder(reminder_id)  #Delete the reminder from the database after it's triggered or prompt the user if they want to delete it

                time.sleep(60)  # Check every minute
        except sqlite3.Error as e:
            logging.error(f"Error checking reminders: {e}")
            time.sleep(60)  # Wait and retry

# === Main App and Sidebar ===
def main_app():
    """Main application UI after login."""
    # ---- SIDEBAR ----
    with st.sidebar:
        selected = option_menu(
            menu_title="EduAssist",
            options=["Academic Assistance", "Reminder Management", "Account Settings", "Analytics", "Logout"],
            icons=['book', 'alarm', 'gear', 'bar-chart-line', 'door-open'],
            menu_icon="mortarboard",
            default_index=0,
        )

        st.sidebar.subheader(f"Logged in as: {st.session_state['username']}")

    # ---- PAGE SELECTION ----
    if selected == "Academic Assistance":
        academic_assistance_page()
    elif selected == "Reminder Management":
        reminder_management_page()
    elif selected == "Account Settings":
        account_settings_page()
    elif selected == "Analytics":
        display_user_analysis(st.session_state['username'])
    elif selected == "Logout":
        st.session_state['logged_in'] = False
        st.session_state['username'] = None
        st.rerun()

    task = threading.Thread(target=check_and_trigger_reminders)
    task.daemon = True  # Daemon threads are abruptly stopped if the program exits
    task.start()

# === Main Execution ===
def main():
    genai.configure(api_key="AIzaSyDlzk8OqZ359GR0st6TnJi01vADcmke7Bo")  #Replace with secure retrieval!
    global model
    model = genai.GenerativeModel("gemini-2.0-flash")
    create_usertable()
    create_activity_tables()  #Create logging tables
    create_reminders_table()

    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
        st.session_state['username'] = None
        st.session_state['page'] = 'login'

    if 'page' not in st.session_state:
        st.session_state['page'] = 'login'

    if not st.session_state['logged_in']:
        if st.session_state['page'] == 'login':
            login_page()
        elif st.session_state['page'] == 'signup':
            signup_page()
    else:
        main_app()

if __name__ == "__main__":
    main()
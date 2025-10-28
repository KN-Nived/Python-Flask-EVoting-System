# --- ESSENTIAL SETUP CODE (At the very top of app.py) ---
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message  # <--- NEW IMPORT
import random
import time
from datetime import datetime, timezone

# ... (rest of the setup code) ...

# --- ELECTION DEADLINE (UPDATED) ---
# Voting ends sharply on October 25, 2025, at 12:00 PM UTC
ELECTION_DEADLINE = datetime(2025, 11, 2, 23, 59, 0, tzinfo=timezone.utc)

def get_election_status():
    now = datetime.now(timezone.utc)

    # If current time is past the deadline, the election is CLOSED.
    if now > ELECTION_DEADLINE:
        return 'CLOSED'
    else:
        # Otherwise, the poll is ACTIVE and open for voting.
        return 'ACTIVE'
# --- 1. APP SETUP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_HARD_TO_GUESS_SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FLASK-MAIL CONFIGURATION (NEW) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'phonetrash74@gmail.com'  #
app.config['MAIL_PASSWORD'] = 'auss zekz anos dece' #
app.config['MAIL_DEFAULT_SENDER'] = 'phonetrash74@gmail.com' #

db = SQLAlchemy(app)
mail = Mail(app) # Initialize Flask-Mail

# Storage for OTPs
OTP_STORAGE = {}






# --- 2. DATABASE MODELS ---

# NEW: Table to store the list of official, eligible IDs (Simulates Aadhaar/Voter Roll)




class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)
    has_voted = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)

    # ... (set_password and check_password methods remain the same)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100))
    information = db.Column(db.Text)
    vote_count = db.Column(db.Integer, default=0)


# --- 3. Initial Data Setup ---
def setup_initial_data():
    # Only create test data if tables are empty
    # (REPLACE the existing Candidate definitions in setup_initial_data() in app.py)
    # (In setup_initial_data() function)

    # --- NEW: Create the list of eligible IDs ---
    if EligibleVoter.query.count() == 0:
        db.session.add_all([
            EligibleVoter(voter_id_number='VOTER100'),
            EligibleVoter(voter_id_number='VOTER101'),
            EligibleVoter(voter_id_number='VOTER102'),
            EligibleVoter(voter_id_number='VOTER103'),
        ])

    # --- Modify the Test Voter Creation ---


        # ... (You can remove the second test voter, newuser, since they won't have a valid ID)
    if Candidate.query.count() == 0:
        db.session.add_all([
            Candidate(
                name='Kshipreet Reji',
                party='DJP',
                information='Kshipreet advocates for modernizing campus outreach. Platform includes launching a student-run fashion magazine, securing dedicated high-speed Wi-Fi zones for content creators, and establishing partnerships with top brands for student internships in the social media industry.'
            ),
            Candidate(
                name='Adheesh Nair',
                party='Congrass',
                information='Adheesh focuses on optimizing the student environment for peak performance. Platform promises guaranteed 5G access across the entire campus, 24/7 access to the campus gym and recreational facilities, and mandatory mental health breaks for students during exam weeks.'
            ),
            Candidate(
                name='Sundar',
                party='Kem Party',
                information='A focused vision on large-scale development and national pride. (jijaji(jehtalal se paise mangne ka mastery) Platform includes accelerated modernization of all core academic buildings, securing funding for international student exchange programs, and establishing a new center for entrepreneurship and innovation for all final-year projects.'
            )
        ])
    db.session.commit()
# --- 3. Initial Data Setup (Simplified) ---
def setup_initial_data():
    # Only create test data if tables are empty
    if Voter.query.count() == 0:
        # Test Voter (Registered and Verified)
        voter1 = Voter(username='testvoter', email='test@example.com', is_verified=True)
        voter1.set_password('password123')
        db.session.add(voter1)

        #admin
        admin_user = Voter(username='admin', email='admin@gov.in', is_verified=True,is_admin=True)  # <-- is_admin is True
        admin_user.set_password('adminpass')  # Set a secure admin password
        db.session.add(admin_user)
    if Candidate.query.count() == 0:
        db.session.add_all([
            Candidate(name='Kshipreet Reji', party='DJP', information='Kshipreet advocates for modernizing campus outreach. Platform includes launching a student-run fashion magazine, securing dedicated high-speed Wi-Fi zones for content creators, and establishing partnerships with top brands for student internships in the social media industry.'),
            Candidate(name='Adheesh Nair', party='Congrass', information='Adheesh focuses on optimizing the student environment for peak performance. Platform promises guaranteed 5G access across the entire campus, 24/7 access to the campus gym and recreational facilities, and mandatory mental health breaks for students during exam weeks.'),
            Candidate(name='Sundar', party='kem party', information='A focused vision on large-scale development and national pride. Platform includes accelerated modernization of all core academic buildings, securing funding for international student exchange programs, and establishing a new center for entrepreneurship and innovation for all final-year projects.')
        ])
    db.session.commit()
# --- NEW: EMAIL SENDER FUNCTION ---
def send_otp_email(recipient_email, otp_code):
    try:
        msg = Message(
            subject='E-Voting Verification Code (OTP)',
            recipients=[recipient_email],
            body=f"Your One-Time Password (OTP) for E-Voting account verification is: {otp_code}\n\nThis code expires in 5 minutes."
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"ERROR SENDING MAIL: {e}")
        return False


def get_current_user():
    """Helper to get the current logged-in voter object."""
    user_id = session.get('user_id')
    return Voter.query.get(user_id) if user_id else None


def login_required(f):
    """Decorator to protect routes from unauthenticated access."""

    def decorated_function(*args, **kwargs):
        if get_current_user() is None:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


# --- 5. REGISTRATION ROUTE (/register) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user():
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # NOTE: voter_id field is no longer collected here.

        # Simple validation for missing fields
        if not (username and email and password):
            flash('All fields are required.', 'danger')
            return render_template('auth.html', page_type='register')

        # Check for duplicate username/email
        if Voter.query.filter_by(email=email).first() or Voter.query.filter_by(username=username).first():
            flash('Username or Email already registered.', 'danger')
            return render_template('auth.html', page_type='register')

        # --- SUCCESSFUL REGISTRATION ---
        new_voter = Voter(username=username, email=email, is_verified=False)  # Simplified model creation
        new_voter.set_password(password)

        db.session.add(new_voter)
        db.session.commit()


        return redirect(url_for('send_otp', email=email))

    return render_template('auth.html', page_type='register')

        # --- Successful Registration ---
    new_voter = Voter(username=username, email=email, voter_id_fk=voter_id, is_verified=False)  # <--- ADD FK
    new_voter.set_password(password)

        # Mark the official ID as used
    eligible_record.is_registered = True

    db.session.add(new_voter)
    db.session.commit()

    flash('Registration successful! Now, verify your email with the OTP.', 'success')
    return redirect(url_for('send_otp', email=email))

    return render_template('auth.html', page_type='register')
    new_voter = Voter(username=username, email=email, is_verified=False)


    new_voter.set_password(password)




    db.session.add(new_voter)
    db.session.commit()

    flash('Registration successful! Now, verify your email with the OTP.', 'success')
        # Redirect to the OTP generation/entry page
    return redirect(url_for('send_otp', email=email))

    return render_template('auth.html', page_type='register')  # Corrected template call


# --- 6. OTP GENERATION AND SENDING ROUTE (/send-otp) ---
@app.route('/send-otp/<email>', methods=['GET'])
# --- 6. OTP GENERATION AND SENDING ROUTE (/send-otp) ---
@app.route('/send-otp/<email>', methods=['GET'])
def send_otp(email):
    voter = Voter.query.filter_by(email=email).first()
    if not voter:
        flash('Voter not found.', 'danger')
        return redirect(url_for('register'))

    # Generate a 6-digit OTP
    otp_code = str(random.randint(100000, 999999))
    OTP_STORAGE[email] = {'otp': otp_code, 'timestamp': time.time()}

    # --- NOW SENDS REAL EMAIL ---
    if send_otp_email(email, otp_code):
        flash(f"A verification code has been sent to your email: {email}. Please check your inbox.", 'info')
    else:
        # Fallback error for presentation
        flash("Could not send email. Please check server settings or try again later.", 'danger')

    # Pass the email to the OTP verification template
    return render_template('auth.html', page_type='otp', email=email)

# --- 7. OTP VERIFICATION ROUTE (/verify-otp) ---
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    email = request.form.get('email')
    entered_otp = request.form.get('otp')

    otp_data = OTP_STORAGE.get(email)

    if not otp_data:
        flash('OTP session expired or invalid. Please re-register or request a new OTP.', 'danger')
        return redirect(url_for('register'))

    # Check for OTP expiry (e.g., 5 minutes)
    if time.time() - otp_data['timestamp'] > 300:  # 300 seconds = 5 minutes
        del OTP_STORAGE[email]
        flash('OTP expired. Please try again.', 'danger')
        return redirect(url_for('send_otp', email=email))

    if entered_otp == otp_data['otp']:
        voter = Voter.query.filter_by(email=email).first()
        if voter:
            voter.is_verified = True
            db.session.commit()

            # Clean up OTP after use
            del OTP_STORAGE[email]

            flash('Email successfully verified! You can now log in.', 'success')
            return redirect(url_for('login'))
    else:
        flash('Invalid OTP.', 'danger')
        return render_template('auth.html', page_type='otp', email=email)  # Corrected template call


# --- 8. LOGIN ROUTE (/login) ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        voter = Voter.query.filter_by(email=email).first()

        if voter and voter.check_password(password):
            if not voter.is_verified:
                flash('Your account is not verified. Please check your email for the OTP or complete verification.',
                      'danger')
                return redirect(url_for('send_otp', email=email))

            # Login successful: store user_id in the session
            session['user_id'] = voter.id
            flash(f'Welcome back, {voter.username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
            return render_template('auth.html', page_type='login')  # Corrected template call

    return render_template('auth.html', page_type='login')  # Corrected template call


# --- 9. LOGOUT ROUTE (/logout) ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



# --- 10. HOME ROUTE (Public Portal) ---
# --- 10. HOME ROUTE (Public Portal) ---
@app.route('/home')
@login_required
def home():
    voter = get_current_user()
    status = get_election_status()

    # 1. Admin redirection logic (must happen first)
    if voter.is_admin:
        return redirect(url_for('admin_results'))

    # 2. Public Voter View Logic
    candidates = Candidate.query.order_by(Candidate.vote_count.desc()).all()
    total_votes = sum(c.vote_count for c in candidates)

    return render_template('home.html',
                           voter=voter,
                           election_status=status,
                           candidates=candidates, # Pass results data
                           total_votes=total_votes) # Pass total votes
# --- 11. ABOUT ROUTE (Contender Info) ---
@app.route('/about')
@login_required
def about():
    # Query all candidates
    candidates = Candidate.query.all()
    return render_template('about.html', candidates=candidates)


# --- 13. ADMIN RESULTS ROUTE (Restricted) ---
@app.route('/admin/results')
@login_required
def admin_results():
    voter = get_current_user()

    # CRITICAL CHECK: Block access if the user is not an admin
    if not voter.is_admin:
        flash('Access Denied. You do not have administrator privileges.', 'danger')
        return redirect(url_for('home'))

    candidates = Candidate.query.order_by(Candidate.vote_count.desc()).all()
    total_votes = sum(c.vote_count for c in candidates)

    return render_template('admin_results.html',candidates=candidates,total_votes=total_votes)
# --- 12. VOTE ROUTE (/vote) ---
@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    voter = get_current_user()

    # Check if the user has already voted
    if voter.has_voted:
        flash('You have already cast your vote.', 'warning')
        return redirect(url_for('home'))

    candidates = Candidate.query.all()

    if request.method == 'POST':
        candidate_id = request.form.get('candidate')
        candidate = Candidate.query.get(candidate_id)

        if candidate:
            # 1. Update candidate vote count
            candidate.vote_count += 1

            # 2. Mark voter as voted
            voter.has_voted = True

            db.session.commit()

            flash(f'Successfully voted for {candidate.name}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid candidate selection.', 'danger')
            return redirect(url_for('vote'))

    # GET request: show the voting form
    return render_template('vote.html', candidates=candidates)


# --- 4. Database Initialization ---
with app.app_context():
    db.create_all()
    setup_initial_data()
    print("Database tables created and initial data populated.")

# --- 5. RUN THE APP (CRITICAL FINAL STEP) ---
if __name__ == '__main__':
    # Flask will start the web server here.
    app.run(debug=True)
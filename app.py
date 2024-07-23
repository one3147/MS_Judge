import uuid, string
from flask import Flask, request, jsonify, make_response,abort
import os
import json
from functools import wraps
import jwt
from flask import Flask, request, jsonify, Blueprint, Response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from urllib.parse import unquote
import datetime
import subprocess
from flask_cors import CORS
import resource
import time
import re
app = Flask(__name__)
api = Blueprint('api', __name__, url_prefix='/api')
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_msjudge'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'th1s_1s_my_S3cr3t_K3y_1!1!'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
from flask import Flask, render_template

# Database 모델 

class Contest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    organizers = db.Column(db.String(255), nullable=False)
    contents = db.Column(db.String(255), nullable=False)
    problems = db.Column(db.String(255), nullable=False)
    participants = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Contest {self.title}>'

class Problem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    time_limit = db.Column(db.Integer, nullable=False)  # 단위: 초
    memory_limit = db.Column(db.Integer, nullable=False)  # 단위: 메가바이트
    counter_example_print = db.Column(db.Boolean, default=False)
    problem_content = db.Column(db.Text, nullable=False)
    problem_input = db.Column(db.Text, nullable=False)
    problem_output = db.Column(db.Text, nullable=False)
    problem_input_example = db.Column(db.Text, nullable=False)
    problem_output_example = db.Column(db.Text, nullable=False)
    problem_answer = db.Column(db.Text, nullable=False)  # 정답 데이터 URL 인코딩된 문자열로 저장
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.problem_content,
            'time_limit': self.time_limit
        }

class User(db.Model):
    id = db.Column(db.String(80), primary_key=True, unique=True)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    is_staff = db.Column(db.Boolean, default=False)
    counter_example = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'joined_at': self.joined_at,
            'is_staff':self.is_staff,
        }
    
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(100), nullable=False)
    question_description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    
class SolvedProblem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    problem_id = db.Column(db.Integer, db.ForeignKey('problem.id'), nullable=False)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    solved_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    problem = db.relationship('Problem', backref=db.backref('solved_problems', lazy=True))
    user = db.relationship('User', backref=db.backref('solved_problems', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'problem_id': self.problem_id,
            'user_id': self.user_id,
            'solved_at': self.solved_at.isoformat()
        }


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(100), nullable=False)
    answer_description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # JWT ID
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    
class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    problem_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    solve_description = db.Column(db.Text, nullable=False)
    
class SolveCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    problem_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.String(80), nullable=False)
    correct = db.Column(db.Boolean, nullable=False)
    your_output = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    source_code = db.Column(db.Text, nullable=False)
    


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', None)
        if not token:
            token = request.cookies.get('access_token', None)
        if token and token.startswith('Bearer '):
            token = token.split(' ')[1]
        if not token:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            return f(*args, **kwargs, user_id=data['sub'])
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
    
    return decorated_function



@api.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or 'id' not in data or 'password' not in data or 'email' not in data:
        return jsonify({"message": "Invalid Request.", "success": False}), 400

    if len(data['password']) < 10:
        return jsonify({"message": "Password must be more than 10 digits."}), 400
    if not re.search(r'\d', data['password']):
        return jsonify({"message": "Password must contain a number."}), 400
    if not re.search(r'[A-Za-z]', data['password']):
        return jsonify({"message": "Password must contain an alphabet."}), 400
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', data['password']):
        return jsonify({"message": "Password must contain a special symbol."}), 400


    id_exists = User.query.filter_by(id=data['id']).first()
    email_exists = User.query.filter_by(email=data['email']).first()

    if id_exists:
        return jsonify({"message": "id is already exists.", "success": False}), 400
    if email_exists:
        return jsonify({"message": "Email is already exists.", "success": False}), 400


    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(id=data['id'], password=hashed_password, email=data['email'],is_staff=False,counter_example=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201



@api.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"success": False}), 400

    id = request.json.get('id', None)
    password = request.json.get('password', None)

    if not id or not password:
        return jsonify({"message": "Invalid Request.", "success": False}), 400

    user = User.query.filter_by(id=id).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_jti = str(uuid.uuid4())
        refresh_jti = str(uuid.uuid4())

        access_token = jwt.encode({
            'sub': id,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'jti': access_jti,  # 액세스 토큰에 JTI 추가
            'token_type': 'access'
        }, app.config['SECRET_KEY'], algorithm='HS256')

        refresh_token = jwt.encode({
            'sub': id,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            'jti': refresh_jti,  # 리프레시 토큰에 JTI 추가
            'token_type': 'refresh'
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify(success=True, access_token=access_token, refresh_token=refresh_token), 200

    return jsonify(success=False), 401

    
@api.route('/access-token', methods=['POST'])
def refresh_access_token():
    token = request.headers.get('Authorization', None)
    if not token:
        return jsonify({"error": "Invalid Request.", "success": False}), 400

    try:
        token = token.split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        if payload['token_type'] != 'refresh':
            raise RuntimeError('Invalid token type')

        if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(payload['exp']):
            raise RuntimeError('Token expired')

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired", "success": False}), 401
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 401
    user_id = payload['sub']
    access_token = jwt.encode({
        'token_type': 'access',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'iat': datetime.datetime.utcnow(),
        'jti': str(uuid.uuid4()),
        'sub': user_id
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({"access_token": access_token})


# 질문 관련

@api.route('/question_upload', methods=['POST'])
@token_required
def upload_question(user_id):
    data = request.json
    if not data or 'title' not in data or 'question_Description' not in data:
        return jsonify({"success": False, "message": "데이터가 누락되었습니다."}), 400
    new_question = Question(
        title=data['title'],
        question_description=data['question_Description'],
        userid=user_id
    )
    db.session.add(new_question)
    db.session.commit()
    return jsonify({"success": True}), 200

@api.route('/answer_upload', methods=['POST'])
@token_required
def upload_answer(user_id):
    data = request.json
    if not data or 'title' not in data or 'answer_Description' not in data or 'question_id' not in data:
        return jsonify({"success": False, "message": "데이터가 누락되었습니다."}), 400
    new_answer = Answer(
        userid = user_id,
        question_id=data['question_id'],
        title=data['title'],
        answer_description=data['answer_Description']
    )
    db.session.add(new_answer)
    db.session.commit()
    return jsonify({"success": True}), 200


# 알고리즘 관련
@api.route('/problem_upload', methods=['POST'])
@token_required
def upload_problem(user_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Invalid Request.'}), 400
        
        new_problem = Problem(
            title=data.get('title'),
            time_limit=int(data.get('time_limit')),
            memory_limit=int(data.get('memory_limit')),
            counter_example_print=data.get('counter_example_print'),
            problem_content=data.get('problem_content'),
            problem_input=data.get('problem_input'),
            problem_output=data.get('problem_output'),
            problem_input_example=json.dumps(data.get('problem_input_example')),
            problem_output_example=json.dumps(data.get('problem_output_example')),
            problem_answer=unquote(data.get('problem_answer'))
        )
        db.session.add(new_problem)
        db.session.commit()
        return jsonify({'success': True, 'message': '문제를 성공적으로 업로드하였습니다.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': '문제 업로드에 실패 하였습니다.', 'error': str(e)}), 401

@api.route('/answer_submit', methods=['POST'])
@token_required
def answer_submit(user_id):
    data = request.get_json()
    language = data.get('language')
    source_code = unquote(data.get('source_code'))
    problem_id = data.get('problem_id')

    # Session.get()을 사용하여 객체를 가져옴
    problem = db.session.get(Problem, problem_id)
    if not problem:
        return jsonify({'success': False, 'message': 'Problem not found'}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 400

    user_dir = os.path.join('submissions', str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    file_ext = {'Python3': 'py', 'C': 'c'}.get(language, 'txt')
    file_path = os.path.join(user_dir, f"{uuid.uuid4()}.{file_ext}")
    


    with open(file_path, 'w') as file:
        file.write(source_code)

    try:
        print(file_path)
        cmd = ['Python3', file_path] if language == 'Python3' else [f'{user_dir}/flag']
        print(cmd)
        print(language)
        if language == 'C':
            subprocess.run(['gcc', '-o', f'{user_dir}/flag', file_path], check=True)
        
        if False:
            pass
        else:
            def stream():
                with app.app_context():
                    try:
                        prob_outputs = json.loads(problem.problem_output_example)
                        prob_inputs = json.loads(problem.problem_input_example)
                        correct = True
                        your_output = ""
                        for inputs, idx in zip(prob_inputs, range(len(prob_inputs))):
                            process = subprocess.Popen(cmd,
                                                stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                text=True)
                            start_time = time.time()
                            print(inputs)
                            process.stdin.write(f'{inputs}\n')
                            process.stdin.flush()
                            output = process.stdout.readline().strip()
                            print(output)
                            end_time = time.time() - start_time
                            if end_time > problem.time_limit:
                                correct = False
                                yield f'data: {{"correct": "X", "message": "Time limit exceeded", "percentage": "{100 / len(prob_inputs) * (idx + 1):.0f}%""}}\n\n'
                                break
                            if output == prob_outputs[idx].strip():
                                yield f'data: {{"correct": "O", "percentage": "{100 / len(prob_inputs) * (idx + 1):.0f}%"}}\n\n'
                            else:
                                correct = False
                                your_output = output
                                yield f'data: {{"correct": "X", "percentage": "{100 / len(prob_inputs) * (idx + 1):.0f}%"}}\n\n'
                                break
                            process.stdin.close()
                            process.terminate()
                            process.wait()
                        if correct:
                            with app.app_context():
                                existing_solve = SolvedProblem.query.filter_by(problem_id=problem_id, user_id=user_id).first()
                                if existing_solve:
                                    pass
                                else:
                                    new_solve = SolvedProblem(problem_id=problem_id, user_id=user_id)
                                    db.session.add(new_solve)
                                    db.session.commit()

                        new_solve_code = SolveCode(
                            problem_id=problem_id,
                            user_id=user_id,
                            correct=correct,
                            your_output=output,
                            expected_output = prob_outputs[idx].strip(),
                            source_code = data.get('source_code')
                        )
                        db.session.add(new_solve_code)
                        db.session.commit()

                    except subprocess.TimeoutExpired:
                        yield f'data: {{"correct": "X", "message": "Time limit exceeded"}}\n\n'
                    finally:
                        process.stdin.close()
                        process.terminate()
                        process.wait()
                        subprocess.run(['rm', '-rf', file_path], check=True)
                        subprocess.run(['rm', '-rf', f'{user_dir}/flag'], check=True)

            return Response(stream(), mimetype='text/event-stream')
    
    except Exception as e:
        if process:
            process.kill()
        subprocess.run(['rm', '-rf', file_path], check=True)
        return jsonify({'success': False, 'message': 'Error executing the submission', 'error': str(e)}), 401

@api.route('/solve_upload', methods=['POST'])
@token_required
def upload_solution(user_id):
    data = request.get_json()
    if not data:
        return jsonify({'message': '데이터가 누락되었습니다.', 'success': False}), 400

    problem_id = data.get('problem_id')
    title = data.get('title')
    solve_description = data.get('solve_Description')

    if not all([problem_id, title, solve_description]):
        return jsonify({'message': '데이터가 누락되었습니다.', 'success': False}), 400

    new_solution = Solution(problem_id=problem_id, title=title, solve_description=solve_description)
    db.session.add(new_solution)
    db.session.commit()

    return jsonify({'success': True})



# 대회 관련
@api.route('/open_contest', methods=['POST'])
@token_required
def open_contest(user_id):
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "대회 개최에 필요한 데이터가 누락되었습니다."}), 400

    required_fields = ["title", "start_time", "end_time", "organizers", "problems"]
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "message": "대회 개최에 필요한 데이터가 누락되었습니다."}), 400
    organizers_str = ', '.join(data['organizers'])
    problems_str = ', '.join(map(str, data['problems']))
    participants_str = organizers_str 

    try:
        start = datetime.datetime.strptime(data['start_time'], '%Y.%m.%d.%H.%M')
        end = datetime.datetime.strptime(data['end_time'], '%Y.%m.%d.%H.%M')
        if start >= end:
            raise ValueError("Start time must be before end time.")
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    new_contest = Contest(
        title=data['title'],
        contents=data['contest_contents'],
        start_time=start,
        end_time=end,
        organizers=organizers_str,
        problems=problems_str,
        participants=participants_str
    )
    db.session.add(new_contest)
    db.session.commit()

    return jsonify({"success": True, "message": "대회를 성공적으로 개최하였습니다."}), 200

@api.route('/attend_contest', methods=['POST'])
@token_required
def attend_contest(user_id):
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "필요한 데이터가 누락되었습니다."}), 400

    contest_id = data.get('contest_id')
    if not contest_id:
        return jsonify({"success": False, "message": "필요한 데이터가 누락되었습니다."}), 400

    try:
        contest = Contest.query.get(contest_id)
        if not contest:
            return jsonify({"success": False, "message": "존재하지 않는 대회입니다."}), 404

        
        if contest.end_time < datetime.datetime.now():
            return jsonify({"success": False, "message": "종료된 대회 입니다."}), 400

        participants_list = contest.participants.split(', ')
        if user_id not in participants_list:
            participants_list.append(user_id)
            contest.participants = ', '.join(participants_list)

            db.session.commit()

            return jsonify({"success": True, "message": "대회 참가 신청에 성공했습니다."}), 200
        else:
            return jsonify({"success": False, "message": "이미 대회에 참가 신청하였습니다."}), 400

    except Exception as e:
        return jsonify({"success": False, "message": "대회 참가 신청에 실패 하였습니다."}), 401

@api.route('/end_contest', methods=['POST'])
@token_required
def end_contest(user_id):
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "대회 종료에 필요한 데이터가 누락되었습니다."}), 400

    contest_id = data.get('contest_id')
    if not contest_id:
        return jsonify({"success": False, "message": "대회 종료에 필요한 데이터가 누락되었습니다."}), 400

    try:
        contest = Contest.query.get(contest_id)
        if not contest:
            return jsonify({"success": False, "message": "존재하지 않는 대회입니다."}), 404

        organizers_list = contest.organizers.split(', ')
        if str(user_id) not in organizers_list:
            return jsonify({"success": False, "message": "해당 대회를 종료할 권한이 없습니다."}), 403

        contest.end_time = datetime.datetime.utcnow()
        
        db.session.commit()

        return jsonify({"success": True, "message": "대회를 성공적으로 종료하였습니다."}), 200

    except Exception as e:
        return jsonify({"success": False, "message": "대회 종료에 실패 하였습니다."}), 401

@api.route('/agree_counter_example', methods=['POST'])
@token_required
def agree_counter_example(user_id):
    data = request.get_json()
    if not data or 'agree' not in data:
        return jsonify({"message": "데이터가 누락되었습니다.", "success": False}), 400

    agree = data['agree']
    if not isinstance(agree, bool):
        return jsonify({"message": "Invalid Request.", "success": False}), 400

    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        user.counter_example = agree
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    
@api.route("/counter_example", methods=['POST'])
@token_required
def counter_example(user_id):
    data = request.get_json()
    if not data or 'solvecode_id' not in data or 'problem_id' not in data:
        return jsonify({"message": "데이터가 누락되었습니다.", "success": False}), 400

    solvecode_id = data['solvecode_id']
    problem_id = data['problem_id']

    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        if not user.counter_example:
            return jsonify({"message": "반례 출력에 동의하지 않으셨습니다.", "success": False}), 403

        counter_example = SolveCode.query.filter(
            SolveCode.id == solvecode_id,
            SolveCode.problem_id == problem_id
        ).first()

        if not counter_example:
            return jsonify({"message": "반례가 존재하지 않습니다.", "success": False})

        return jsonify({
            "success": True,
            "expected_output": counter_example.expected_output,
            "your_output": counter_example.your_output
        })

    except Exception as e:
        return jsonify({"message": "처리 중 오류가 발생했습니다.", "success": False, "error": str(e)}), 500
    



@api.route('/problems', methods=['GET'])
@token_required
def problems(user_id):
    problems = Problem.query.all() 
    solved_problems = SolvedProblem.query.filter_by(user_id=user_id).all()
    solved_problem_ids = {solved.problem_id for solved in solved_problems}
    
    problems_list = [
        {
            'id': problem.userid,
            'title': problem.title,
            'solved': problem.id in solved_problem_ids
        }
        for problem in problems
    ]
    
    return jsonify(success=True, message="probs", problems=problems_list), 200

@api.route('/questions', methods=['GET'])
@token_required
def questions(user_id):
    questions = Question.query.all() 
    questions_list = [
        {
            'idx':question.id,
            'id': question.userid,
            'title': question.title,
            'submit_date': question.created_at
        }
        for question in questions
    ]
    
    return jsonify(success=True, message="questions", problems=questions_list), 200

@api.route('/answers', methods=['GET'])
@token_required
def answers(user_id):
    answers = Answer.query.all() 
    answers_list = [
        {
            'question_id': answer.id,
            'title': answer.title,
            'answer_description': answer.answer_description
        }
        for answer in answers
    ]
    
    return jsonify(success=True, message="answers", answers=answers_list), 200

@api.route('/contests', methods=['GET'])
@token_required
def contests(user_id):
    contests = Contest.query.all() 
    contests_list = [
        {
            'title': contest.title,
            'start_time': contest.start_time,
            'end_time': contest.end_time,
            "contests_description": contest.contents,
            "problems": contest.problems
        }
        for contest in contests
    ]
    
    return jsonify(success=True, message="contests", contests=contests_list), 200

    """
    class Contest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    organizers = db.Column(db.String(255), nullable=False)
    problems = db.Column(db.String(255), nullable=False)
    participants = db.Column(db.String(255), nullable=False)_summary_
    """
    

@api.route("/problems/<int:idx>", methods=['GET'])
@token_required
def problem_detail(user_id, idx):
    try:
        problem = db.session.get(Problem, idx)
        if not problem:
            return jsonify({"message": "문제가 존재하지 않습니다.", "success": False}), 404

        return jsonify({
            "success": True,
            "title": problem.title,
            "time_limit": problem.time_limit,
            "memory_limit": problem.memory_limit,
            "counter_example_print": problem.counter_example_print,
            "problem_content": problem.problem_content,
            "problem_input": problem.problem_input,
            "problem_output": problem.problem_output,
            "problem_input_example": problem.problem_input_example.replace('"',"'"),
            "problem_output_example": problem.problem_output_example.replace('"',"'")
        }), 200

    except Exception as e:
        return jsonify({"message": "처리 중 오류가 발생했습니다.", "success": False, "error": str(e)}), 500

@app.route("/", methods=["GET"])
def index():
    # 쿠키에서 'access_token' 확인
    logged_in = True if request.cookies.get("access_token") else False
    # 로그인 상태에 따라 템플릿 렌더링
    return render_template('index.html', logged_in=logged_in)

@app.route('/mypage', methods=['GET', 'PATCH'])
@token_required  # 사용자 인증 데코레이터 가정
def mypage(user_id):
    user = User.query.filter_by(id=user_id).first()
    
    if request.method == 'GET':
        if user:
            return render_template('mypage.html', user=user.to_dict())
        else:
            return jsonify({'message': 'User not found'}), 404

    elif request.method == 'PATCH':
        data = request.get_json()
        try:
            if 'email' in data:
                user.email = data['email']
            if 'password' in data and data['password'] != '':
                hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
                user.password = hashed_password
            else:
                password = user.password
            if 'counter_example' in data:
                user.counter_example = data['counter_example']
            db.session.commit()
            return jsonify({'message': 'User updated successfully'}), 200
        except Exception as e:
            return jsonify({'message': str(e)}), 400
        
@app.route("/login",methods=["GET"])
def login():
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(jsonify({"message": "Logged out successfully"}), 200)
    token = request.headers.get('Authorization', None)
    if token:
        token = token.split(' ')[1]
    if not token:
        token = request.cookies.get('refresh_token', None)

    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data['token_type'] != 'refresh':
                raise RuntimeError('Invalid token type')

            if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(data['exp']):
                raise RuntimeError('Token expired')
            jti = data['jti']
            blacklisted_token = TokenBlacklist(jti=jti)
            db.session.add(blacklisted_token)
            db.session.commit()

            # 쿠키에서 토큰 삭제
            response.set_cookie('access_token', '', expires=0)
            response.set_cookie('refresh_token', '', expires=0)
            return response

        except jwt.ExpiredSignatureError:
            response.set_cookie('access_token', '', expires=0)
            response.set_cookie('refresh_token', '', expires=0)
            return jsonify({"error": "Token expired", "success": False}), 401
        except Exception as e:
            response.set_cookie('access_token', '', expires=0)
            response.set_cookie('refresh_token', '', expires=0)
            return jsonify({"error": str(e), "success": False}), 401

    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response

@app.route("/open_contest",methods=["GET"])
def open_contest():
    return render_template('open_contest.html')

@app.route('/attend_contest', methods=['GET'])
def contest_list():
    contests = Contest.query.all()
    return render_template('contest_list.html', contests=contests)

@app.route('/attend_contest/<int:contest_id>', methods=['GET'])
def show_attend_contest_page(contest_id):
    contest = Contest.query.get_or_404(contest_id)
    return render_template('attend_contest.html', contest=contest)

@app.route('/question_board', methods=['GET'])
def questions_list():
    return render_template('question_list.html')

@app.route('/question/<int:idx>', methods=['GET'])
def question_detail(idx):
    question = Question.query.get(idx)
    if not question:
        abort(404)
    
    answers = Answer.query.filter_by(question_id=idx).all()
    return render_template('question_detail.html', question=question, answers=answers)

@app.route('/question_upload', methods=['GET'])
def questions_upload():
    return render_template('question_upload.html')

@app.route('/problem_upload', methods=['GET'])
def problems_upload():
    return render_template('problem_upload.html')

@app.route('/problem_list', methods=['GET'])
def problem_list():
    problems = Problem.query.all()
    return render_template('problem_list.html', problems=problems)

@app.route('/problem_detail/<int:idx>', methods=['GET'])
def problem_detail(idx):
    return render_template('problem_detail.html')

@app.route('/submit_code/<int:idx>', methods=['GET'])
def code_submit(idx):
    return render_template('submit_code.html')

@app.route('/contest/<int:contest_idx>', methods=['GET'])
@token_required
def contest_start(contest_idx, user_id):
    contest = Contest.query.filter_by(id=contest_idx).first()
    if not contest:
        return "대회가 존재하지 않습니다.", 404

    if user_id not in contest.participants.split(', '):
        return abort(401)

    if datetime.datetime.utcnow() > contest.end_time:
        contest_ended = True
    else:
        contest_ended = False

    problem_ids = [int(pid) for pid in contest.problems.split(', ')]
    problems = Problem.query.filter(Problem.id.in_(problem_ids)).order_by(Problem.id).all()
    problems_dict = {p.id: p.to_dict() for p in problems}
    ordered_problems = [problems_dict[pid] for pid in problem_ids if pid in problems_dict]

    labels = list(string.ascii_uppercase)
    if len(ordered_problems) > len(labels):
        labels *= (len(ordered_problems) // len(labels) + 1)
    labels = labels[:len(ordered_problems)]

    participants = contest.participants.split(', ')
    scores = {}
    for participant in participants:
        scores[participant] = 0
        for problem_id in problem_ids:
            print(problem_id)
            solved_count = SolvedProblem.query.filter(
                SolvedProblem.user_id == participant,
                SolvedProblem.solved_at <= contest.end_time,
                SolvedProblem.problem_id == problem_id
            ).count()
            scores[participant] += solved_count * 100

    scores_sorted = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    rank = {name: idx + 1 for idx, (name, score) in enumerate(scores_sorted)}

    return render_template('start_contest.html', contest=contest, problems=zip(ordered_problems, labels),
                           scores=scores_sorted, rank=rank, contest_ended=contest_ended)

@app.route('/api/problems/<int:problem_id>/status', methods=['GET'])
@token_required
def check_problem_status(problem_id,user_id):
    solved = db.session.query(SolvedProblem).filter_by(user_id=user_id, problem_id=problem_id).first()
    return jsonify({
        'success': True,
        'solved': bool(solved)
    })
    
@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')


@app.route('/counter_example/<int:problem_idx>')
@token_required
def counter_example(problem_idx, user_id):
    user = User.query.get_or_404(user_id)
    problem = Problem.query.get_or_404(problem_idx)
    solve_codes = SolveCode.query.filter_by(problem_id=problem_idx, user_id=user_id).all()

    can_show_counter_example = user.counter_example and problem.counter_example_print

    return render_template('counter_example.html', solve_codes=solve_codes, problem_idx=problem_idx, can_show_counter_example=can_show_counter_example)


@app.route('/solve_code/<int:code_id>', methods=['GET'])
@token_required
def get_solve_code(code_id, user_id):
    solve_code = SolveCode.query.get_or_404(code_id)
    if solve_code.user_id != user_id:
        return jsonify({"message": "Unauthorized access to the solve code.", "success": False}), 403

    # URL 디코드
    decoded_code = unquote(solve_code.source_code)

    return render_template('solve_code_detail.html', solve_code=decoded_code, solve=solve_code)


@app.route('/solution/<int:contest_id>/<int:problem_id>')
@token_required
def show_solution(contest_id, problem_id, user_id):
    contest = Contest.query.get_or_404(contest_id)
    if datetime.datetime.utcnow() <= contest.end_time:
        return abort(403, description="대회가 아직 종료되지 않았습니다.")

    problem = Problem.query.get_or_404(problem_id)
    if not problem:
        return "문제가 존재하지 않습니다.", 404

    decoded_answer = unquote(problem.problem_answer)

    return render_template('problem_solution.html', problem=problem, decoded_answer=decoded_answer)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.session.query(TokenBlacklist).delete()
        db.session.commit()
    app.register_blueprint(api)
    app.run(debug=True, host='0.0.0.0', port=9999)
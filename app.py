from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///brawl.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Моделі бази даних
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    trophies = db.Column(db.Integer, default=0)
    brawlers = db.relationship('Brawler', backref='user', lazy=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Brawler(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    power = db.Column(db.Integer, default=1)
    trophies = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Ініціалізація бази даних
with app.app_context():
    db.create_all()

# Стартові бравлери
STARTER_BRAWLERS = [
    {"name": "Shelly", "power": 1},
    {"name": "Colt", "power": 1},
    {"name": "Nita", "power": 1}
]

# Маршрути Flask
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('home.html', user=user)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists")
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Додаємо стартових бравлерів
        for brawler in STARTER_BRAWLERS:
            new_brawler = Brawler(
                name=brawler['name'],
                power=brawler['power'],
                user_id=new_user.id
            )
            db.session.add(new_brawler)
        
        db.session.commit()
        
        session['user_id'] = new_user.id
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            user.last_seen = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('index'))
        
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/brawlers')
def brawlers():
    # Перевірка авторизації
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Отримання даних користувача
    user = User.query.get(session['user_id'])
    
    # Перевірка що користувач існує
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    
    # Отримання бравлерів користувача
    brawlers = Brawler.query.filter_by(user_id=user.id).all()
    user.brawlers = brawlers  # Додаємо бравлерів до об'єкта користувача
    
    # Передача даних у шаблон
    return render_template(
        'brawlers.html',
        user=user,
        current_time=datetime.utcnow()  # Додаткові дані при потребі
    )

@app.route('/game')
def game():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('game.html', user=user)

@app.route('/get_match')
def get_match():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    user = User.query.get(session['user_id'])
    
    # Спрощена логіка підбору суперника
    opponent = User.query.filter(
        User.trophies.between(user.trophies-200, user.trophies+200),
        User.id != user.id
    ).order_by(db.func.random()).first()
    
    if not opponent:
        opponent = User.query.filter(
            User.id != user.id
        ).order_by(db.func.random()).first()
    
    # Вибираємо випадкових бравлерів
    player_brawler = random.choice(user.brawlers)
    opponent_brawler = random.choice(opponent.brawlers)
    
    return jsonify({
        "player": {
            "username": user.username,
            "brawler": player_brawler.name,
            "power": player_brawler.power
        },
        "opponent": {
            "username": opponent.username,
            "brawler": opponent_brawler.name,
            "power": opponent_brawler.power
        }
    })

@app.route('/end_match', methods=['POST'])
def end_match():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.json
    user = User.query.get(session['user_id'])
    brawler = Brawler.query.filter_by(name=data['brawler'], user_id=user.id).first()
    
    if not brawler:
        return jsonify({"error": "Brawler not found"}), 404
    
    # Оновлення трофеїв
    if data['result'] == 'win':
        trophies_gain = 8
        user.trophies += trophies_gain
        brawler.trophies += trophies_gain
    else:
        trophies_loss = -4 if brawler.trophies > 0 else 0
        user.trophies += trophies_loss
        brawler.trophies += trophies_loss
    
    db.session.commit()
    
    return jsonify({
        "message": "Match result saved",
        "new_trophies": user.trophies,
        "brawler_trophies": brawler.trophies
    })

# HTML шаблони (зберігаються у папці templates/)

if __name__ == '__main__':
    app.run(debug=True)
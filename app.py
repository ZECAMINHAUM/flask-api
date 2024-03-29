from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import ( 
    JWTManager, 
    jwt_required, 
    create_access_token, 
    get_jwt_identity,
    get_raw_jwt
)
from flask_cors import CORS
import bcrypt



#URI Do Banco de dados
SQLALCHEMY_DATABASE_URI = "mysql+mysqldb://{username}:{password}@{hostname}/{databasename}".format(
    username = "username",
    password = "password",
    hostname = "hostname",
    databasename = "databasename",
)

#iniciando app
app = Flask(__name__)
CORS(app)

#Banco de dados config 
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_POOL_RECYCLE'] = 299
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


#jwt config
app.config['JWT_SECRET_KEY'] = 'secret'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']


db = SQLAlchemy(app)
ma = Marshmallow(app)

jwt = JWTManager(app)
blacklist = set()


class User(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(4096))
    senha = db.Column(db.String(4096))


class Item(db.Model):
    __tablename__ = "Items"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(4096))


class UserSchema(ma.ModelSchema):
    class Meta:
        model = User

class ItemSchema(ma.ModelSchema):
    class Meta:
        model = Item

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

#Rota para registro
@app.route('/registro', methods=['POST'])
def register():
    data = request.form
    users = User.query.filter_by(nome=data['nome']).first()
    if users is None:

        senha = bcrypt.hashpw(password=data['senha'].encode('utf-8'), salt=bcrypt.gensalt())
        newUser = User(nome = data['nome'], senha=senha)
        db.session.add(newUser)
        db.session.commit()
        return jsonify({ 'success': True }), 201

    return jsonify({ 'success': False, 'errors': { 'nome': 'Usuário já cadastrado' } }), 400


#Rota para login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    users = User.query.filter_by(nome=data['nome']).first()
    if users is None:
        return jsonify({ 'success': False, 'errors': { 'nome': 'Nome ou senha incorreto' }}), 400

    senha = str(users.senha).encode('utf-8')
    cmpsenha = str(data['senha']).encode('utf-8')
    
    if bcrypt.checkpw(cmpsenha, senha):
        token = create_access_token(users.nome)
        return jsonify({ 'success': True, 'token': token }), 200
    return jsonify({ 'success': False, 'errors': { 'nome': 'Nome ou senha incorreto' }  }), 400

#Rota para logout 
@app.route('/logout', methods=['GET'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({ 'success': True }), 200

#Rota para obter todos os Nomes
@app.route('/items', methods=['GET'])
@jwt_required
def index():
    items = Item.query.all()
    items_schema = UserSchema(many=True)


    return jsonify({ 'success': True, 'items': items_schema.dump(items) }), 200


#Rota para cadastrar
@app.route('/item/adicionar', methods=['POST'])
@jwt_required
def create():
    data = request.json
    items = Item.query.filter_by(nome=data['nome']).first()
    if items is None:
        item = Item(nome = data['nome'])
        db.session.add(item)
        db.session.commit()

        return jsonify({ 'success': True }), 201
    else:
        return jsonify({ 'success': False, 'errors': { 'Nome': 'Nome Já Cadastrado' } }), 400


@app.route('/item/atualizar/<id>', methods=['POST'])
@jwt_required
def update(id):
    data = request.json
    print(data['nome'])
    if data['nome'] is None:
        return jsonify({ 'success': False, 'errors': { 'nome': 'O nome não pode ser nulo' }}), 400
    else: 
        item = Item.query.filter_by(id=id).first()
        if item is None:
            return jsonify({ 'success': False, 'errors': { 'item': 'Item não encontrado!'}}), 400
        else:  
            item.nome = data['nome']
            db.session.commit()

        return jsonify({ 'success': True }), 200


@app.route('/item/deletar/<id>', methods=['GET'])
@jwt_required
def delete(id):
    item = Item.query.filter_by(id=id).first()
    if item is None:
        return jsonify({ 'success': False, 'errors': { 'item': 'Item não encontrado!'}}), 400
    else:
        db.session.delete(item)
        db.session.commit()
    
    return jsonify({ 'success': True }), 200


app.run(debug=True)


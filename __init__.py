from flask import Flask
from flask import render_template
from flask import json
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


from flask import Flask, render_template, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from datetime import timedelta

from flask import Flask, render_template, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt, jwt_required, JWTManager
from datetime import timedelta

app = Flask(__name__)                                                                                                                  
                                                                                                                                       
# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Clé secrète
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # Jeton valable 1h

jwt = JWTManager(app)

@app.route('/')
def hello_world():
    return render_template('accueil.html')

# Route de connexion qui génère un JWT avec rôle
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # Vérification des identifiants (exemple basique)
    if username == "admin" and password == "password":
        role = "admin"
    elif username == "user" and password == "password":
        role = "user"
    else:
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # Création du JWT avec le rôle inclus
    access_token = create_access_token(identity=username, additional_claims={"role": role})
    return jsonify(access_token=access_token)

# Route protégée par un JWT valide
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(msg=f"Bienvenue {current_user} ! Cette page est protégée."), 200

# Route admin protégée (uniquement accessible aux utilisateurs ayant le rôle "admin")
@app.route("/admin", methods=["GET"])
@jwt_required()
def admin_route():
    claims = get_jwt()  # Récupérer les données du JWT
    if claims.get("role") != "admin":
        return jsonify(msg="Accès refusé, admin requis"), 403

    return jsonify(msg="Bienvenue, Admin !"), 200

if __name__ == "__main__":
    app.run(debug=True)


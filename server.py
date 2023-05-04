from flask import Flask, render_template, request, jsonify, make_response, redirect, json, flash

import Levenshtein
import difflib
import bcrypt
import hashlib
import os

import threading
import secrets


from os import path, walk

extra_dirs = ['./templates/','./db/']
extra_files = extra_dirs[:]
for extra_dir in extra_dirs:
    for dirname, dirs, files in walk(extra_dir):
        for filename in files:
            filename = path.join(dirname, filename)
            if path.isfile(filename):
                extra_files.append(filename)


app = Flask(__name__)
server_secret = ''

app.secret_key = server_secret.encode()



class ExpiringDict(dict):
    def __init__(self):
        pass
    def get(self, p):
        retval = self[p]
        del self[p]
        return retval

dynamic_download_links = ExpiringDict()

sort_results = lambda x: {k: v for k, v in sorted(x.items(), reverse=True, key=lambda item: item[1])}



with open(f'content', 'r', encoding='utf-8') as file:
        bookdb = eval(file.read())



def similarity(ox, oy):
    lscore = 0
    x, y = ox.split()[:5], oy.split()[:5]
    for i in x:
        for j in y:
            ratio = difflib.SequenceMatcher(None, i, j).ratio()
            if ratio < .7: continue
            lscore += ratio
    return pow(lscore, 2)/(abs(len(ox)-len(oy))+1)



def authenticate(uname, psw):
    try:
        with open(f'./db/{uname}/data', 'r') as file:
            hashed = file.read().encode('utf-8')
        return bcrypt.checkpw(psw.encode('utf-8'), hashed)
    except: return False
    
def generate_hash(psw):
    return bcrypt.hashpw(psw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def md5crypt(data):
    return hashlib.md5(data.encode()).hexdigest()
    
def write_credinental(uname, psw, otherdata):
    
    if os.path.isfile(f'./db/EMAILS/{md5crypt(otherdata[0])}'): return False
    else:
        with open(f'./db/EMAILS/{md5crypt(otherdata[0])}', 'x') as file: pass

    if os.path.isfile(f'./db/STUDENTIDS/{md5crypt(otherdata[1])}'): return False
    else:
        with open(f'./db/STUDENTIDS/{md5crypt(otherdata[1])}', 'x') as file: pass

    if os.path.exists(f'./db/{uname}'): return False
    else: os.mkdir(f'./db/{uname}')
    
    with open(f'./db/{uname}/data', 'w') as file:
        file.write(generate_hash(psw))
    with open(f'./db/{uname}/other', 'w') as file:
        file.write('\n'.join(otherdata))
    with open(f'./db/{uname}/sessioncookie', 'w') as file:
        file.write(secrets.token_urlsafe(256))
    return True

def get_sessioncookie(uname):
    try:
        with open(f'./db/{uname}/sessioncookie', 'r') as file:
            return file.read()
    except: return False
    

def search_entries(phr):
    phr = phr.strip().lower()
    if phr == "":
        return [{"search_result":f'<a href="{bookdb[i]}">{i}</a>'} for i in bookdb] 
    collect = {}
    exact = []
    exact_match = False
    for i in bookdb:
        if i.lower().startswith(phr):
            exact.append({"search_result":f'<a href="{bookdb[i]}">{i}</a>'})
            exact_match = True
        if not exact_match and phr in i:
            collect[i] = 1-(i.index(phr)/len(i))
    if exact_match: res = sorted(exact, key=lambda x: len(x["search_result"]))
    else: res = [{"search_result":f'<a href="{bookdb[i]}">{i}</a>'} for i in sort_results(collect)]
    if not res:
        collect = {}
        for i in bookdb:
            collect[i] = similarity(i.lower(), phr)
        res = [{"search_result":f'<a href="{bookdb[i]}">{i}</a>'} for i in sort_results(collect)]
    return res[:50]




@app.route("/")
def index():
    if 'session' not in request.cookies or 'username' not in request.cookies :
        return make_response(redirect('login'))
    if get_sessioncookie(request.cookies['username']) != request.cookies['session']:
        return make_response(redirect('login'))
    return render_template("index.html", username=request.cookies['username'])



    
@app.route("/login")
def login():
    if 'session' in request.cookies and 'username' in request.cookies :
        if get_sessioncookie(request.cookies['username']) == request.cookies['session']:
            return make_response(redirect('/'))
    return render_template("login.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")
    
@app.route("/login_process", methods=["POST","GET"])
def login_process():
    print(request.form)
    if authenticate(request.form['uname'], request.form['psw']):
        resp = make_response(redirect("/"))
        resp.set_cookie('session', get_sessioncookie(request.form['uname']))
        resp.set_cookie('username', request.form['uname'])
    else:
        resp = make_response(redirect("login"))
    return resp
    
@app.route("/signup_process", methods=["POST","GET"])
def signup_process():
    user_exists = not write_credinental(request.form['uname'], request.form['password'], [request.form['email'], request.form['schoolid']])
    if user_exists:
        #flash("Girdiğiniz biligilerden biriyle daha önceden kayıt oluşturulmuş.")
        return render_template("signup_fail.html")
    return make_response(redirect("/"))
    
    
@app.route("/livesearch", methods=["POST","GET"])
def livesearch():
    searchbox = request.form.get("text").lower()
    print('Search term:', searchbox)
    return jsonify(search_entries(searchbox))



@app.route("/hosted_files", methods=["POST","GET"])
def hosted_files():
    if 'session' not in request.cookies or 'username' not in request.cookies :
        return make_response(redirect('login'))
    if get_sessioncookie(request.cookies['username']) != request.cookies['session']:
        return make_response(redirect('login'))
    filename = request.args['get']
    with open(f'hosted_files//{filename}', 'rb') as file:
        binary_pdf = file.read()
    response = make_response(binary_pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename={filename}'
    return response

if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run("0.0.0.0", debug=False, extra_files=extra_files)

#!/usr/bin/python
# -*- coding:utf-8 -*-

import sys
import os
import os.path
reload(sys)
sys.setdefaultencoding('utf-8')

sys.path.append(os.path.join(os.getcwd(), ".."))


import sqlite3
import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import os.path
import datetime
import string
import hashlib
import random

from tornado.options import define, options

define("port", default=8890, help="run on the given port", type=int)
DOCUMENT_ROOT = os.path.dirname(__file__)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/statics", Statics),
            (r"/success", Success),
            (r"/cancel", Cancel),
            (r"/test", Test),
            (r"/auth/login", AuthHandler),
            (r"/auth/password", PasswordHandler),
            (r"/log/(?P<year>\d+)/(?P<month>\d+)/(?P<day>\d+)", LogHandler),
            (r"/supper", Cancel),
            ]
        settings = dict(
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/auth/login",
            template_path=os.path.join(DOCUMENT_ROOT, "templates"),
            static_path=os.path.join(DOCUMENT_ROOT, "static"),
            xsrf_cookies=True,
            autoescape=None,
            xheasers=True

            )
        
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json:
            return None
        return tornado.escape.json_decode(user_json)

    def get_db(self):
        db = sqlite3.connect(os.path.join(DOCUMENT_ROOT, 'database.db'))
        return db


class PasswordHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render("password.html")

    def post(self):
        password1 = self.get_argument("password1")
        password2 = self.get_argument("password2")
    
        if password1 != password2:
            self.write("两次输入的密码不匹配！")
        else:
            db = self.get_db()
            member_id = self.get_secure_cookie("user")
            cursor = db.cursor()
            hasher = SHA1PasswordHasher()
            salt = hasher.get_salt()
            encoded = hasher.encode(password1, salt)
            cursor.execute("update members set password=? where id=?",
                           (encoded, member_id))
            db.commit()
            self.write("密码修改成功！")
            self.flush()

class AuthHandler(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        name = self.get_argument("name")
        name = name.strip()
        password = self.get_argument("password")
        password = password.strip()

        hasher = SHA1PasswordHasher()
        db = self.get_db()
        cursor = db.cursor()
        cursor.execute("select id, password from members where "
                       "name=?", (name,))
        result = cursor.fetchone()
        if not result:
            self.write("用户名不正确")
            self.flush()
        else:
            member_id, encoded = result
            if hasher.verify(password, encoded):
                self.set_secure_cookie("user", str(member_id))
                self.redirect(self.get_argument("next", "/"))
            else:
                self.write("密码错误！")
                self.flush()

def get_subscribed(cursor, member_id):
    now = datetime.datetime.now()
    start_time = datetime.datetime(now.year, now.month, now.day, 17)
    cursor.execute("select id, category from supper where member=? "
                   "and ts>?", (member_id, start_time))
    return cursor.fetchone()

class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        now = datetime.datetime.now()
        if 17 <= now.hour < 18:
            db = self.get_db()
            cursor = db.cursor()
            member_id = self.get_secure_cookie("user")
            result = get_subscribed(cursor, member_id)
            if result:
                cursor.execute("select name from category where id=?",
                               (result[1],))
                category = cursor.fetchone()[0]
                self.render("supper.html", category=category)
            else:
                cursor.execute("select id, name from category;")
                categories = cursor.fetchall()
                self.render("index.html", categories=categories)
        else:
            self.render("idel.html")

    def post(self):
        member_id = self.get_secure_cookie("user")
        category = self.get_argument("category")
        db = self.get_db()
        now = datetime.datetime.now()
        cursor = db.cursor()
        record = get_subscribed(cursor, member_id)

        if record:
            self.write("今天你已经订过饭啦！")
            self.flush()
        else:
            cursor.execute("INSERT INTO supper (member, category, ts) "
                           "values (?,?,?)",
                    (member_id, category, datetime.datetime.now()))
            db.commit()
            self.redirect("/supper")
            self.flush()

class SHA1PasswordHasher(object):
    algorithm = "sha1"

    def get_salt(self, allowed_chars=string.letters+string.digits,
                 length=12):
        result = [random.choice(allowed_chars) for i in xrange(length)]

        return "".join(result)
        
            
    def encode(self, password, salt):
        hashed = hashlib.sha1(salt+password).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hashed)

    def verify(self, password, encoded):
        algorithm, salt, hashed = encoded.split("$", 2)
        encoded2 = self.encode(password, salt)
        return encoded == encoded2

    
class Cancel(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        member_id = self.get_secure_cookie("user")
        db = self.get_db()
        cursor = db.cursor()
        supper_id, category_id = get_subscribed(cursor, member_id)
        cursor.execute("select name from category where id=?",
                       (category_id,))
        category = cursor.fetchone()[0]
        self.render("supper.html", category=category)
        
    def post(self):
        now = datetime.datetime.now()
        if 17 <= now.hour < 18:
            member_id = self.get_secure_cookie("user")
            db = self.get_db()
            cursor = db.cursor()
            record = get_subscribed(cursor, member_id)
            if not record:
                self.write("您今天没有订饭，不用取消！")
            else:
                supper_id, category_id = record
                try:
                    cursor.execute("delete from supper where id=?",
                                   (supper_id,))
                    db.commit()
                    self.write("取消成功！")
                    self.flush()
                except:
                    self.write("取消失败！")
                    self.flush()


class Success(BaseHandler):
    def get(self):
        self.render("success.html")

class Statics(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        member_id = self.get_secure_cookie("user")
        if member_id == "5" or member_id == "44":
            db = self.get_db()
            cursor = db.cursor()
            now = datetime.datetime.now()
            cursor.execute("select member, category from supper where ts > ?",
                  (datetime.datetime(now.year, now.month, now.day, 17),))
            records = cursor.fetchall()
            count = len(records)
            D = {}
            for member_id, category_id in records:
                cursor.execute("select name from members where id=?",
                               (member_id,))
                name = cursor.fetchone()[0]
                if D.has_key(category_id):
                    D[category_id].append(name)
                else:
                    D[category_id] = [name]
            D2 = {}
            for category_id in D:
                cursor.execute("select name from category where id=?",
                               (category_id,))
                name = cursor.fetchone()[0]
                D2[name] = D[category_id]
            
            self.render("static.html", count=count, D2=D2)

        else:
            self.write("未授权访问！")
            if random.randint(0, 10) == 6:
                self.write("您的IP地址已经被记录下来，请耐心等待网警敲门！")
            self.flush()

class LogHandler(BaseHandler):
    def get(self, year, month, day):
        year, month, day = map(int, [year, month, day])
        member_id = self.get_secure_cookie("user")
        if member_id == "5" or member_id == "44":
            db = self.get_db()
            cursor = db.cursor()
            start = datetime.datetime(year, month, day)
            stop = start + datetime.timedelta(days=1)
            cursor.execute("select members.name as name, ts as data "
                           "from members left join supper "
                           "on members.id = supper.member "
                           "where  ts > ?  and ts < ? order by ts",
                           (start, stop))
            logs = cursor.fetchall()
            count = len(logs)
            logs = [(name, d.split(" ")[1][:8])
                     for name, d in logs]
            self.render("log.html", count=count, logs=logs)
        else:
            self.write("无授权访问！")
            self.flush()

class Test(BaseHandler):
    def get(self):
        self.render("test.html")


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port, "0.0.0.0")
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()

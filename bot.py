#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Bot of team yeti_rose Thot 2013 by gossel_j

import os
import re
import urllib
from base64 import b64decode
from datetime import datetime
import time
from Queue import Queue
from tempfile import NamedTemporaryFile
from cookielib import CookieJar
import xml.etree.ElementTree as ET
import subprocess

from twisted.python import failure
from twisted.words.protocols import irc
from twisted.internet import protocol, reactor, error, defer
from twisted.web.client import CookieAgent, RedirectAgent, Agent
from twisted.web.iweb import IBodyProducer

from letters import BigLetters, SmallLetters


class PostProducer(IBodyProducer):
    def __init__(self, data={}):
        self.body = urllib.urlencode(data)
        self.length = len(self.body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


class CouponSession(object):
    def __init__(self, queue):
        self.login = 'login_u'
        self.password = '*********'
        self.login_url = 'http://portal.thot.episeclab.org/accounts/login/'
        self.coupon_url = 'http://portal.thot.episeclab.org/items/coupons/validate/'
        self.cookieJar = CookieJar()
        self.agent = CookieAgent(RedirectAgent(Agent(reactor)), self.cookieJar)
        self.ping()

    def getCookie(self, name):
        for cookie in self.cookieJar:
            if cookie.name == name:
                return cookie.value
        return None

    def ping(self):
        d = self.agent.request("HEAD", self.coupon_url)
        d.addCallback(self._pingCallback)

    def _pingCallback(self, resp):
        if resp.request.absoluteURI == self.login_url:
            d = self.agent.request("POST", self.login_url, None, PostProducer({'csrfmiddlewaretoken': self.getCookie('csrftoken'), 'username': self.login, 'password': self.password}))
            d.addCallback(self._pingCallbackBis)

    def _pingCallbackBis(self, resp):
        if resp.request.absoluteURI == self.login_url:
            print 'ERROR CANT LOGIN'
            reactor.stop()
        self.ping()

    def __call__(self, coupon):
        d = self.agent.request("POST", self.coupon_url)
        r = self.s.post(self.coupon_url, data={'csrfmiddlewaretoken': self.s.cookies['csrftoken'], 'passphrase': coupon})
        if r.url == self.login_url:
            r = self.s.post(self.login_url, data={'csrfmiddlewaretoken': self.s.cookies['csrftoken'], 'username': self.login, 'password': self.password})
            if r.url == self.login_url:
                print 'ERROR CANT LOGIN'
                exit()
            self.ping()
            self(coupon)


class CouponSessionManager(object):
    def __init__(self, nb):
        self.queue = Queue()
        self.objs = []
        for i in xrange(nb):
            self.objs.append(CouponSession(self.queue))
        for s in self.objs:
            reactor.callInThread(s.run)

    def __call__(self, coupon):
        if coupon:
            self.queue.put(coupon)

    def kill(self):
        for i in xrange(len(self.objs)):
            self.queue.put(None)
        self.queue.join()

    def ping(self):
        for s in self.objs:
            s.ping()


class VerticalCoupon(object):
    def __init__(self, sender):
        self.current = None
        self.sender = sender

    def prepare(self, coupon):
        self.current = []

    def add(self, coupon):
        if self.current is not None:
            self.current.append(coupon)

    def process(self, coupon):
        if self.current is not None:
            map(self.sender, map(''.join, zip(*self.current)))
            self.current = None


class HalfCoupon(object):
    def __init__(self, sender):
        self.current = None
        self.sender = sender

    def first(self, coupon):
        self.current = coupon

    def second(self, coupon):
        if self.current:
            f = True
            out = ''
            for n in xrange(min(len(coupon), len(self.current))):
                out += self.current[n] if f else coupon[n]
                f = not f
            self.sender(out)


class MD5DecryptCoupon(object):
    def __init__(self, sender):
        self.pool = urllib3.PoolManager(timeout=5)
        self.sender = sender

    def __call__(self, coupon):
        try:
            text = ET.XML(self.pool.request('GET', 'http://md5.noisette.ch/md5.php', fields={'hash': coupon}).data).findtext('string')
        except urllib3.exceptions.TimeoutError:
            text = ''
        if text:
            self.sender(text)
            return
        text = self.pool.request('GET', 'http://md5.darkbyte.ru/api.php', fields={'q': coupon}).data
        if text:
            self.sender(text)


class GrosCoupon(object):
    def __init__(self, sender):
        self.current = None
        self.sender = sender

    def prepare(self, coupon):
        self.current = []

    def add(self, coupon):
        if self.current is not None:
            self.current.append(coupon)
            if len(self.current) == 7:
                self.process()

    def process(self):
        ret = []
        while any(self.current):
            tmp = []
            for n, l in enumerate(self.current):
                s = l[:7]
                s += ' ' * (7 - len(s))
                tmp.append(s)
                self.current[n] = l[8:]
            ret.append(tmp)
        self.current = None
        txt = ''
        for b in ret:
            try:
                n = BigLetters.index(b)
            except ValueError:
                print '### MISSING LETTER'
                for l in b:
                    print '### %s' % l
                return
            else:
                txt += SmallLetters[n]
        self.sender(txt)


class OCRCoupon(object):
    def __init__(self, sender):
        self.pool = urllib3.PoolManager(timeout=5)
        self.sender = sender

    def __call__(self, coupon):
        p = os.pipe()
        if os.write(p[1], self.pool.request('GET', coupon).data) <= 0:
            map(os.close, p)
            return
        os.close(p[1])
        f = NamedTemporaryFile(suffix='.pnm')
        if subprocess.call('png2pnm', stdin=p[0], stdout=f.fileno()) != 0:
            os.close(p[0])
            f.close()
            return
        os.close(p[0])
        for i in xrange(4):
            f.seek(0)
            if i != 0:
                if subprocess.call(('convert', f.name, '-rotate', '90', f.name)) != 0:
                    f.close()
                    return
            try:
                txt = subprocess.check_output(('timeout', '3', 'ocrad'), stdin=f.fileno()).strip().replace(' ', '')
            except subprocess.CalledProcessError:
                pass
            else:
                if '\n' not in txt:
                    self.sender(txt)


class PHPCoupon(object):
    regexs = (
        re.compile(r'time_sleep_until\s*\(.+?\)\s*;'),
        re.compile(r'usleep\s*\(.+?\)\s*;'),
        re.compile(r'sleep\s*\(.+?\)\s*;'))
    fwords = ('system', 'exec', 'passthru', 'proc', 'parse_ini_file', 'show_source', 'fork', 'open', 'shell', 'posix', 'syslog', 'ini_alter')

    def __init__(self, sender):
        self.sender = sender

    def __call__(self, coupon):
        for w in self.fwords:
            if w in coupon:
                return
        for r in self.regexs:
            coupon = r.sub('', coupon)
        try:
            self.sender(subprocess.check_output(('timeout', '3', 'php', '-r', coupon)))
        except subprocess.CalledProcessError:
            pass


class MyTimer(object):
    def __init__(self, callback, limit=60):
        self.last = time.time()
        self.callback = callback
        self.limit = limit

    def __call__(self, *args, **kwargs):
        t = time.time()
        if t - self.last >= self.limit:
            self.callback(*args, **kwargs)
            self.last = t


class CouponPwner(object):
    b64_regex = re.compile(r'[A-Za-z0-9+/]+={1,4}')

    def __init__(self):
        self.sender = CouponSessionManager(4)
        self.sender_ping = MyTimer(self.sender.ping, 60)
        self.vertical = VerticalCoupon(self.sender)
        self.half = HalfCoupon(self.sender)
        self.md5_decrypt = MD5DecryptCoupon(self.sender)
        self.ocr = OCRCoupon(self.sender)
        self.gros = GrosCoupon(self.sender)
        self.php = PHPCoupon(self.sender)
        self.regexs = (
            (re.compile(r'^Coupon "(?P<coupon>.+)" valide par la team .*$'), self.nothing),
            (re.compile(r'^C?[oO]upon: (?P<coupon>[0-9a-f]{32})$'), self.sender),
            (re.compile(r'^(?P<coupon>[0-9a-f]{32}) :nopuoC$'), self.reversed_md5),
            (re.compile(r'^Coupon: (?P<coupon>http://.+\.png)$'), self.ocr),
            (re.compile(r'^Coupon: (?P<coupon>[()+*/%0-9-]+)$'), self.calc),
            (re.compile(r'^Coupon "(?P<coupon>[0-9a-f]{32})"$'), self.sender),
            (re.compile(r'^Coupon \(word md5\): (?P<coupon>[0-9a-f]{32})$'), self.md5_decrypt),
            (re.compile(r'^Couphpon: (?P<coupon>.+)$'), self.php),
            (re.compile(r'^(?P<coupon>coupons verticaux:)$'), self.vertical.prepare),
            (re.compile(r'^(?P<coupon>[0-9a-f]+)$'), self.vertical.add),
            (re.compile(r'^(?P<coupon>ze end)$'), self.vertical.process),
            (re.compile(r'^(?P<coupon>GROCOUPON)$'), self.gros.prepare),
            (re.compile(r'^C?[oO]upon: (?P<coupon>[A-Za-z0-9+/]+={1,4})$'), self.b64),
            (re.compile(r'^Coupon "(?P<coupon>[A-Za-z0-9+/]+={1,4})"$'), self.b64),
            (re.compile(r'^(?P<coupon>={1,4}[A-Za-z0-9+/]+) :nopuoC$'), self.reversed_b64),
            (re.compile(r'C\.u\.o\.:\.(?P<coupon>[0-9a-f.]{32})$'), self.half.first),
            (re.compile(r'\.o\.p\.n\. (?P<coupon>[0-9a-f.]{32})$'), self.half.second),
            (re.compile(r'^Coupons: (?P<coupon>.+)$'), self.multi),
            (re.compile(r'^pokecoupon:.*(?P<coupon>[0-9a-f]{32}).*$'), self.sender),
            (re.compile(r'^(?P<coupon>[ #]*)$'), self.gros.add))

    def __call__(self, line):
        for r, f in self.regexs:
            ret = r.match(line)
            if ret:
                f(ret.group('coupon'))
                return
        self.sender_ping()

    def kill(self):
        self.sender.kill()

    def nothing(self, c):
        pass

    def normal(self, coupon):
        if coupon:
            if self.b64_regex.match(coupon):
                self.sender(b64decode(coupon))
            else:
                self.sender(coupon)

    def b64(self, coupon):
        self.sender(b64decode(coupon))

    def calc(self, coupon):
        try:
            self.sender(str(eval(coupon)))
        except ZeroDivisionError:
            pass

    def reversed_md5(self, coupon):
        self.sender(coupon[::-1])
        self.sender(coupon)

    def reversed_b64(self, coupon):
        self.b64(coupon[::-1])

    def multi(self, coupons):
        map(self.normal, coupons.split())


connectionDone = failure.Failure(error.ConnectionDone())
connectionDone.cleanFailure()


class ThotBot(irc.IRCClient):
    def __init__(self, nickname):
        self.channel = '##esl'
        self.michel_nick = 'm1ch3l!~m1ch3l@secl.epitech.eu'
        self.pwner = CouponPwner()
        self.nickname = nickname

    def connectionLost(self, reason=connectionDone):
        self.pwner.kill()

    def signedOn(self):
        print '### Signed in ###'
        self.join(self.channel)

    def joined(self, channel):
        print '### channel %s joined ###' % channel

    def privmsg(self, user, channel, msg):
        if user == self.michel_nick:
            self.pwner(msg)
            now = datetime.now()
            print '%02d:%02d %s' % (now.hour, now.minute, msg)

    def kickedFrom(self, channel, kicker, msg):
        print '### kicked by %s : %s' % (kicker, msg)
        self.join(self.channel)

    def nickChanged(self, nick):
        print '### nick changed to : %s' % nick
        self.nickname += '_'
        self.setNick(self, self.nickname)

    def irc_ERR_NICKNAMEINUSE(self, prefix, params):
        self.nickname += '_'
        self.register(self.nickname)


class ThotBotFactory(protocol.ClientFactory):
    def __init__(self, nb):
        self.nickname = 'B00m5haka_%d' % nb

    def buildProtocol(self, addr):
        p = ThotBot(self.nickname)
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        connector.connect()


if __name__ == '__main__':
    print 'Welcome !'
    reactor.connectTCP('irc.freenode.org', 6667, ThotBotFactory(42))
    print 'Reactor starting...'
    reactor.run()
    print 'Reactor quit...'

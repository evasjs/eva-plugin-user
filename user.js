/**
 * @Author: eason
 * @Date:   2017-05-30T13:40:00+08:00
 * @Last modified by:   eason
 * @Last modified time: 2017-07-09T13:39:42+08:00
 */
const invariant = require('invariant');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pick = require('lodash.pick');

module.exports = function createUser(options = {}) {
  invariant(options.jwt, 'createUser: you need provide jwt options.');
  invariant(options.jwt.secretKey, 'createUser: you need provide jwt secretKey.');

  const {
    secretKey,
    algorithm = 'HS256',
    expiresIn = '2 days',
    audience = 'evaer',
    issuer = 'eva-server',
    jwtid,
    subject = 'evaer',
  } = options.jwt;

  return {
    namespace: 'User',

    models: {
      schema: {
        username: { type: String, required: true, trim: true, unique: true },
        password: { type: String, required: true },
        nickname: { type: String, trim: true, default: '🐱' },
        /* eslint-disable */
        avatar: { type: String, default: 'https://ooo.0o0.ooo/2017/06/06/593582f8bd5b9.png' },
        avatarBig: { type: String, default: 'https://ooo.0o0.ooo/2017/06/06/593582f8b88eb.png' },
        /* eslint-enable */
      },
      options: {
        timestamps: true,
        safe: true,
        strict: true,
        toJSON: { virtuals: false },
        versionKey: false,
      },
      pre: {
        save(_, utils, next) {
          if (this.isNew) {
            bcrypt.genSalt(10, (errSalt, salt) => {
              if (errSalt) return next(errSalt);
              return bcrypt.hash(this.password, salt, (errHash, hash) => {
                if (errHash) return next(errHash);
                this.password = hash;
                return next();
              });
            });
          } else {
            next();
          }
        },
      },
      methods: {
        comparePassword(_, utils, password, cb) {
          bcrypt.compare(password, this.password, (err, isMatched) => {
            if (err) return cb(err);
            return cb(null, isMatched);
          });
        },
        changePassword(_, utils, password, cb) {
          bcrypt.genSalt(10, (errSalt, salt) => {
            if (errSalt) return cb(errSalt);
            return bcrypt.hash(password, salt, (errHash, hash) => {
              if (errHash) return cb(errHash);
              this.password = hash;
              return cb(null);
            });
          });
        },
        sign(_, utils, cb) {
          const info = pick(this.toJSON(), ['_id', 'username', 'nickname', 'avatar']); // omit(this.toJSON(), ['password']);
          return jwt.sign(
            info,
            secretKey,
            {
              algorithm,
              expiresIn,
              audience,
              issuer,
              jwtid,
              subject,
            },
            (err, token) => {
              if (err) return cb(err);
              return cb(null, token);
            },
          );
        },
      },
      statics: {
        fetch(_, __, option, cb) {
          if (cb === undefined) {
            cb = option;
            this
              .find({})
              .select({ password: false })
              .limit(10)
              .exec(cb);
          } else {
            const { offset, limit } = option;
            this
              .find({})
              .select({ password: false })
              .skip(offset)
              .limit(limit)
              .exec(cb);
          }
        },
        fetchOne(_, __, username, cb) {
          this
            .findOne({ username })
            .exec(cb);
        },
        create(_, __, { username, password, nickname, avatar }, cb) {
          // User == this
          this.exists(username, (err, exists) => {
            if (err) return cb(err);

            if (exists) {
              const error = new Error('用户名已存在!');
              error.json = { status: 400, errcode: 400101, errmsg: '用户名已存在!' };
              return cb(error);
            }

            const user = new this({ username, password, nickname, avatar });
            return user.save((errSaved, isSaved) => {
              if (errSaved) return cb(err);
              return cb(null, !!isSaved);
            });
          });
        },
        exists(_, __, username, cb) {
          return this
            .findOne({ username })
            .exec((err, exists) => {
              if (err) return cb(err);
              return cb(null, !!exists);
            });
        },
        verify(_, utils, token, cb) {
          return jwt.verify(
            token,
            secretKey,
            {
              algorithm,
              audience,
              issuer,
              subject,
              maxAge: expiresIn,
              jwtid,
            },
            (err, user) => {
              if (err) return cb(err);

              return this.findOne({ username: user.username }).exec(cb);
            },
          );
        },
      },
    },

    routes: {
      '/user': {
        get: ['requireAuthorized', 'format/offset&limit', 'list'],
        // post: ['filter/username&password', 'filter/twicepassword', 'create'],
      },
      '/user/:id': {
        get: ['requireAuthorized', 'filter/uid/not/exist', 'retrieve'],
        post: ['requireAuthorized', 'update'],
        delete: ['requireAuthorized', 'delete'],
      },
      '/signup': {
        post: ['filter/username&password', 'filter/twicepassword', 'create'],
      },
      '/auth': {
        post: ['filter/username&password', 'authorize'],
      },
      '/resetPassword': {
        get: ['filter/token', 'filter/twicepassword', 'updatePassword'],
        post: ['requireAuthorized', 'filter/twicepassword', 'updatePassword'],
      },
    },

    middlewares: {
      'format/offset&limit'(_, { req, next }) {
        req.offset = +req.offset || 0;
        req.limit = +req.limit || 10;
        next();
      },
      'filter/username&password'(_, { req, next }) {
        const { username, password } = req.body;
        if (!(username && password)) {
          const error = new Error('用户名或密码不能为空!');
          error.json = { status: 400, errcode: 400102, errmsg: '用户名或密码不能为空!' };
          next(error);
        } else {
          next();
        }
      },
      'filter/twicepassword'(_, { req, next }) {
        const { password, repassword } = req.body;
        if (!(password && repassword)) {
          const error = new Error('用户名或密码不能为空!');
          error.json = { status: 400, errcode: 400103, errmsg: '用户名或密码不能为空!' };
          next(error);
        } else if (password !== repassword) {
          const error = new Error('密码不一致!');
          error.json = { status: 400, errcode: 400104, errmsg: '密码不一致!' };
          next(error);
        } else {
          next();
        }
      },
      'filter/username/not/exist'({ User }, { req, next }) {
        const username = req.body.username;
        User
          .findOne({ username })
          .exec((err, user) => {
            if (err) {
              next(err);
            } else if (!user) {
              const error = new Error('用户不存在!');
              error.json = { status: 400, errcode: 400105, errmsg: '用户不存在!' };
              next(error);
            } else {
              req.user = user;
              next();
            }
          });
      },
      'filter/uid/not/exist'({ User }, { req, next }) {
        const id = req.params.id;
        User
          .findOne({ _id: id })
          .select({ password: false })
          .exec((err, user) => {
            if (err) {
              next(err);
            } else if (!user) {
              const error = new Error('用户不存在!');
              error.json = { status: 400, errcode: 400106, errmsg: '用户不存在!' };
              next(error);
            } else {
              req.user = user;
              next();
            }
          });
      },
      'filter/token'({ User }, { req, next }) {
        const token = req.query.token;
        if (!token) {
          const error = new Error('需登录！');
          error.json = { status: 400, errcode: 400107, errmsg: '需登录！' };
          return next(error);
        }

        return User.verify(token, (err, user) => {
          if (err) return next(err);

          req.user = user;
          return next();
        });
      },
      'requireAuthorized'({ User }, { req, next }) {
        const authorization = req.headers.authorization || '';
        const token = authorization.split(' ').pop();
        if (!authorization || !token) {
          const error = new Error('需登录！');
          error.json = { status: 400, errcode: 400108, errmsg: '需登录！' };
          return next(error);
        }

        return User.verify(token, (err, user) => {
          if (err) return next(err);

          req.user = user;
          return next();
        });
      },
    },

    handlers: {
      'list'({ User }, { req, res, next }) {
        const { offset, limit } = req.query;
        User
          .fetch({ offset, limit }, (err, users) => {
            if (err) return next(err);
            return res.status(200).json(users);
          });
      },
      'create'({ User }, { req, res, next }) {
        const { username, password, nickname, avatar } = req.body;

        User.create({ username, password, nickname, avatar }, (err) => {
          if (err) return next(err);

          return res.sendStatus(201);
        });
      },
      'retrieve'(_, { req, res }) {
        return res.status(200).json(req.user);
      },
      'updatePassword'(_, { req, res, next }) {
        const user = req.user;
        const password = req.body.password;
        user.changePassword(password, (err) => {
          if (err) {
            err.json = { errcode: 400109, errmsg: err.message };
            return next(err);
          }

          return res.sendStatus(201);
        });
      },
      'update'(_, { req, res, next }) {
        const user = req.user;
        const { nickname, avatar } = req.body;
        user.nickname = nickname;
        user.avatar = avatar;
        user.save((err) => {
          if (err) {
            err.json = { errcode: 400110, errmsg: err.message };
            return next(err);
          }

          return res.sendStatus(201);
        });
      },
      'delete'(_, { req, res, next }) {
        const user = req.user;
        user.remove((err) => {
          if (err) {
            err.json = { errcode: 400113, errmsg: err.message };
            return next(err);
          }

          return res.sendStatus(204);
        });
      },
      'authorize'({ User }, { req, res, next }) {
        const { username, password } = req.body;

        User.fetchOne(username, (err, user) => {
          if (err) return next(err);

          if (!user) {
            const error = new Error('用户不存在!');
            error.json = { status: 400, errcode: 400111, errmsg: '用户不存在!' };
            return next(error);
          }

          return user.comparePassword(password, (comparedErr, isMatched) => {
            if (comparedErr) return next(err);

            if (!isMatched) {
              const error = new Error('密码错误!');
              error.json = { status: 400, errcode: 400112, errmsg: '密码错误!' };
              return next(error);
            }

            return user.sign((signErr, token) => {
              if (signErr) return next(signErr);
              return res.status(200).json(token);
            });
          });
        });
      },
    },
  };
};

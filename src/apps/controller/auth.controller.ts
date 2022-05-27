import { OAuth2Client } from "google-auth-library";
import axios from "axios";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import db from "../models";

const { sequelize } = db;
import {
  checkPasswordRequirement,
  getUserByEmail,
} from "../helpers/users.helper";
import {
  createConfirmationEmail,
  resendConfirmationEmail,
} from "../helpers/email.helper";

const Users = db.users;
const UsersProfile = db.usersProfile;
const UsersTokens = db.usersTokens;
const UsersSession = db.usersSession;
const UsersOauth = db.usersOauth;

const jwtSecret: string = process.env.JWT_SECRET as string;

const createJWToken = (userId: string) => {
  const rawToken = {
    selector: crypto.randomBytes(10).toString("hex"),
    token: crypto.randomBytes(25).toString("hex"),
    userId: userId,
  };
  const result = {
    rawToken: rawToken,
    jwtToken: jwt.sign({ rawToken }, jwtSecret),
  };

  return result;
};

exports.createNewAccount = async (req: any, res: any) => {
  const { email, password, firstName, lastName } = req.body;

  const existUser = await Users.findOne({
    where: {
      email,
    },
  });

  if (existUser)
    return res.status(400).send({
      Error: "Email already registered",
      Email_verification: existUser.verification,
    });

  const checkPasswordResult: any = await checkPasswordRequirement(password);
  if (checkPasswordResult.length)
    return res
      .status(400)
      .send({ validationFailed: true, checkPasswordResult });

  const hashedNewPwd = bcrypt.hashSync(password, 8);

  const transaction = await sequelize.transaction();
  let userData: any = {};
  try {
    userData = await Users.create(
      {
        email,
        password: hashedNewPwd,
      },
      { transaction }
    );

    await UsersProfile.create(
      {
        user_id: userData.id,
        first_name: firstName,
        last_name: lastName,
      },
      { transaction }
    );

    await transaction.commit();
  } catch (e) {
    if (transaction) await transaction.rollback();
    console.log(e);
    return res.status(500).send({ error: e });
  }

  await createConfirmationEmail(userData.id);

  return res.sendStatus(200);
};

exports.resendVerification = async (req: any, res: any) => {
  const { email } = req.body;

  const userData = await Users.findOne({ where: { email: email } });
  if (!userData) return res.status(404).send({ error: "Account not found!" });

  const result = await resendConfirmationEmail(userData.id);
  if (result !== true) return res.status(400).send(result);

  return res.sendStatus(200);
};

exports.verifyEmail = async (req: any, res: any) => {
  const { tokens } = req.params;

  const tokenData = await UsersTokens.findOne({ where: { tokens } });

  if (!tokenData || tokenData.token_type !== "Email Verification")
    return res.status(400).send({ error: "Invalid Tokens!" });

  const userData = await Users.findOne({ where: { id: tokenData.user_id } });

  if (!userData)
    return res
      .status(500)
      .send({ error: "Something Wrong, please try again!" });

  userData.verification = 1;
  userData.status = 1;
  userData.total_login += 1;

  await userData.save();

  await tokenData.destroy();

  // Do auto login here
  const jwtResult = createJWToken(userData.id);

  await UsersSession.create({
    user_id: userData.id,
    selector: jwtResult.rawToken.selector,
    hashed_token: crypto
      .createHash("md5")
      .update(jwtResult.rawToken.token)
      .digest("hex"),
    created_on: Math.floor(new Date().getTime() / 1000),
    session_method: "Email",
    last_seen: Math.floor(new Date().getTime() / 1000),
  });

  return res.status(200).send({ authToken: jwtResult.jwtToken });
};

exports.doLogin = async (req: any, res: any) => {
  const { email, password } = req.body;

  if (!email && !password)
    return res
      .status(400)
      .send({ error: "Email address & Password is required" });

  const userData = await getUserByEmail(email);

  if (!userData) return res.status(404).send({ error: "Account not found!" });

  if (!userData.verification)
    return res.status(400).send({
      error: "Haven't verified your email account!",
      Email_verification: userData.verification,
    });

  if (!userData.status)
    return res.status(400).send({
      error: "Account not active!",
      Email_verification: userData.verification,
    });

  const checkPassword = bcrypt.compareSync(password, userData.password);

  if (!checkPassword)
    return res.status(400).send({ error: "Password Account not match!" });

  const jwtResult = createJWToken(userData.id);

  const sessionsData = await UsersSession.create({
    user_id: userData.id,
    selector: jwtResult.rawToken.selector,
    hashed_token: crypto
      .createHash("md5")
      .update(jwtResult.rawToken.token)
      .digest("hex"),
    created_on: Math.floor(new Date().getTime() / 1000),
    session_method: "Email",
    last_seen: Math.floor(new Date().getTime() / 1000),
  });

  userData.last_login = Math.floor(new Date().getTime() / 1000);
  userData.total_login += 1;
  await userData.save();

  if (!sessionsData)
    return res.status(500).send({ error: "Login Failed!, please try again" });

  return res.status(200).send({ authToken: jwtResult.jwtToken });
};

exports.checkAuth = async (req: any, res: any, next: any) => {
  const authToken = req.headers.authtoken;
  if (!authToken)
    return res
      .status(401)
      .send({ error: "Access Denied, authToken not found!" });

  let result: any = {};
  try {
    result = jwt.verify(authToken, jwtSecret);
  } catch (e) {
    return res.status(400).send(e);
  }

  if (!result) return res.sendStatus(401);

  const sessionData = await UsersSession.findOne({
    where: {
      selector: result.rawToken.selector,
      hashed_token: crypto
        .createHash("md5")
        .update(result.rawToken.token)
        .digest("hex"),
    },
  });

  if (!sessionData) return res.sendStatus(401);

  req.userId = sessionData.user_id;
  req.sessionsId = sessionData.id;

  sessionData.last_seen = Math.floor(new Date().getTime() / 1000);
  await sessionData.save();

  return next();
};

exports.doLogout = async (req: any, res: any) => {
  const { userId, sessionsId } = req;

  await UsersSession.destroy({
    where: {
      id: sessionsId,
      user_id: userId,
    },
  });

  return res.sendStatus(200);
};

exports.doLoginOauth = async (req: any, res: any) => {
  const { type, jwtToken } = req.body;
  let userId: string = "";
  let oauthUserId: string = "";
  let oauthEmail: string = "";
  let firstName: string = "";
  let lastName: string = "";
  let payload: any = "";

  console.log(type);
  if (type === "Google") {
    const client = await new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    let ticket: any = {};
    try {
      ticket = await client.verifyIdToken({
        idToken: jwtToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
    } catch (e) {
      return res.status(400).send(e);
    }

    if (!ticket) return res.sendStatus(400);

    payload = ticket.getPayload();
    firstName = payload.given_name;
    lastName = payload.family_name;
    oauthUserId = payload.sub;
    oauthEmail = payload.email;
  } else if (type === "Facebook") {
    // request Facebook access_token
    const fbRequest: any = await axios
      .get(
        `https://graph.facebook.com/oauth/access_token?client_id=${process.env.FB_APP_ID}&client_secret=${process.env.FB_APP_SECRET}&grant_type=client_credentials`
      )
      .catch((e) => {
        console.log(e);
      });
    const fbAccessToken: any = fbRequest.data.access_token;

    const checkFbToken: any = await axios
      .get(
        `https://graph.facebook.com/debug_token?input_token=${jwtToken}&access_token=${fbAccessToken}`
      )
      .catch((e) => {
        console.log(e.response.data);
      });

    if (!checkFbToken.data.data.is_valid) return res.sendStatus(400);
    oauthUserId = checkFbToken.data.data.user_id;

    const fbProfileData: any = await axios
      .get(
        `https://graph.facebook.com/me?fields=id,name,email&access_token=${jwtToken}`
      )
      .catch((e) => {
        console.log(e.response.data);
      });

    const { name: fbName, email: fbEmail } = fbProfileData.data;
    oauthEmail = fbEmail;
    const [first, last] = fbName.split(" ");
    firstName = first;
    lastName = last;
  }

  const existOauth = await UsersOauth.findOne({
    where: {
      type: type,
      oauth_user_id: oauthUserId,
    },
  });

  if (oauthUserId && existOauth) {
    console.log("oauth exist");
    userId = existOauth.user_id;
  }

  const existEmail = await Users.findOne({
    where: {
      email: oauthEmail,
    },
  });

  if (oauthEmail && !existOauth) {
    if (existEmail) {
      console.log("email exist, create oauth");

      await UsersOauth.create({
        user_id: existEmail.id,
        type: "Google",
        oauth_user_id: oauthUserId,
        connected_at: Math.floor(new Date().getTime() / 1000),
      });

      userId = existEmail.id;
    }
  }

  if (!existEmail && !existOauth && oauthEmail) {
    console.log("email not exist, create user & oauth");

    const transaction = await sequelize.transaction();
    let userData: any = {};
    try {
      userData = await Users.create(
        {
          email: oauthEmail,
          password: "",
          verification: 1,
          status: 1,
        },
        { transaction }
      );

      await UsersProfile.create(
        {
          user_id: userData.id,
          first_name: firstName,
          last_name: lastName,
        },
        { transaction }
      );

      await UsersOauth.create(
        {
          user_id: userData.id,
          type: "Google",
          oauth_user_id: oauthUserId,
          connected_at: Math.floor(new Date().getTime() / 1000),
        },
        { transaction }
      );

      await transaction.commit();
    } catch (e) {
      if (transaction) await transaction.rollback();
      console.log(e);
      return res.status(500).send({ error: e });
    }

    userId = userData.id;
  }

  if (userId) {
    const userData = await Users.findOne({ where: { id: userId } });
    userData.last_login = Math.floor(new Date().getTime() / 1000);
    userData.total_login += 1;

    await userData.save();

    const jwtResult = createJWToken(userId);

    const sessionsData = await UsersSession.create({
      user_id: userId,
      selector: jwtResult.rawToken.selector,
      hashed_token: crypto
        .createHash("md5")
        .update(jwtResult.rawToken.token)
        .digest("hex"),
      created_on: Math.floor(new Date().getTime() / 1000),
      session_method: type,
      last_seen: Math.floor(new Date().getTime() / 1000),
    });

    if (!sessionsData)
      return res.status(500).send({ error: "Login Failed!, please try again" });

    return res.status(200).send({ authToken: jwtResult.jwtToken });
  }

  return res.status(500).send({ error: "Login Failed!, please try again" });
};

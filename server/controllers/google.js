"use strict";

const { ValidationError } = require("@strapi/utils").errors;

module.exports = {
  async getCredentials(ctx) {
    ctx.body = await strapi
      .plugin("strapi-google-auth")
      .service("google")
      .getGoogleCredentials();
  },
  async createCredentials(ctx) {
    try {
      await strapi
        .plugin("strapi-google-auth")
        .service("google")
        .createGoogleCredentials(ctx.request.body);

      ctx.body = { status: true };
    } catch (error) {
      console.log(error);
      ctx.body = { status: false };
    }
  },
  async initLogin(ctx) {
    try {
      let loginURL = await strapi
        .plugin("strapi-google-auth")
        .service("google")
        .createAuthURL();
      ctx.body = loginURL;
    } catch (error) {
      ctx.badRequest("Error fetching the Login URL", null);
    }
  },
  async getUserProfile(ctx) {
    try {
      const idToken = ctx.request.body.idToken
        ? ctx.request.body.idToken
        : null;
      if (!idToken) {
        throw new ValidationError("Invalid/Missing idToken", null);
      }

      let user = await strapi
        .plugin("strapi-google-auth")
        .service("google")
        .getUserProfile(idToken);

      ctx.body = user;
    } catch (error) {
      ctx.badRequest("Error occured while fetching the user profile", null);
    }
  },
  async getUserDetails(ctx) {
    const token = ctx.request.header.authorization
      ? ctx.request.header.authorization.replace("Bearer ", "")
      : null;
    if (!token) {
      ctx.badRequest("Invalid/Missing token", null);
    }
    try {
      let userData = await strapi
        .plugin("strapi-google-auth")
        .service("google")
        .getUserDetailsFromToken(token);
      ctx.body = userData;
    } catch (error) {
      ctx.badRequest("Invalid/Missing token", null);
    }
  },
  async updatePassword(ctx) {
    const token = ctx.request.header.authorization
      ? ctx.request.header.authorization.replace("Bearer ", "")
      : null;
    if (!token) {
      ctx.badRequest("Invalid/Missing token", null);
    }
    const password = ctx.request.body.password;
    try {
      let userData = await strapi
        .plugin("strapi-google-auth")
        .service("google")
        .getUserDetailsFromToken(token);
      await strapi
        .plugin("users-permissions")
        .service("user")
        .edit(userData.id, {
          password,
        });
      ctx.body = { status: true };
    } catch (error) {
      console.log(error);
      ctx.badRequest("Error", "Couldn't update the user");
    }
  },
};

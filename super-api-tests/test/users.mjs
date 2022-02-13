import { expect } from "chai";
import supertest from "supertest";

const request = supertest("https://gorest.co.in/public-api/");

const TOKEN =
  "6dc353df7c107b9cf591463edb36e13dbc182be021562024473aac00cd19031c";

describe("Users", () => {
  it("GET /users", (done) => {
    request.get(`/users?access-token=${TOKEN}`).end((err, res) => {
      expect(res.body.data).to.not.be.empty;
      done();
    });
  });

  it("GET /users", () => {
    return request.get(`/users?access-token=${TOKEN}`).then((res) => {
      expect(res.body.data).to.not.be.empty;
    });
  });

  it("GET /users/:id", () => {
    return request.get(`/users/1?access-token=${TOKEN}`).then((res) => {
      expect(res.body.data.id).to.not.be.eq(1);
    });
  });

  it("GET /users with querry param", () => {
    const url = `users?access-token=${TOKEN}&page=1&gender=female&status=active`;

    return request.get(url).then((res) => {
      expect(res.body.data).to.not.be.empty;

      res.body.data.forEach((data) => {
        expect(data.gender).to.eq(`female`);
        expect(data.status).to.eq(`active`);
      });
    });
  });

  it(`POST /users generating users in bulk using post call`, () => {
    const data = {
      email: `user${Math.floor(Math.random() * 10000)}@example.com`,
      name: `user-${Math.floor(Math.random() * 10000)}`,
      gender: "male",
      status: "inactive",
    };
    return request
      .post(`users`)
      .set("Authorization", "Bearer " + TOKEN)
      .send(data)
      .then((res) => {
        expect(res.body.data).to.not.be.empty;
        expect(res.body.data).to.deep.include(data);
      });
  });
});

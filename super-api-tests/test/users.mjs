import { expect } from "chai";
import supertest from "supertest";
import dotenv from "dotenv";

dotenv.config();

const request = supertest(process.env.API_BASE_URL || "https://gorest.co.in/public-api/");

const TOKEN = process.env.API_TOKEN || "your-api-token-here";

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

  it(`put / users: id`, async () => {
    // First create a user to update
    const createData = {
      email: `user${Math.floor(Math.random() * 10000)}@example.com`,
      name: `user-${Math.floor(Math.random() * 10000)}`,
      gender: "male",
      status: "inactive",
    };
    
    const createResponse = await request
      .post(`users`)
      .set("Authorization", "Bearer " + TOKEN)
      .send(createData);
    
    const userId = createResponse.body.data.id;
    
    // Now update the user
    const updateData = {
      status: "active",
      name: `test-user-${Math.floor(Math.random() * 9999)}`,
    };

    const response = await request
      .put(`/users/${userId}`)
      .set("Authorization", "Bearer " + TOKEN)
      .send(updateData);
    
    console.log(response.body.data);
    expect(response.body.data).to.deep.include(updateData);
  });

  it(`delete /users/:id`, async () => {
    // First create a user to delete
    const createData = {
      email: `user${Math.floor(Math.random() * 10000)}@example.com`,
      name: `user-${Math.floor(Math.random() * 10000)}`,
      gender: "male",
      status: "active",
    };
    
    const createResponse = await request
      .post(`users`)
      .set("Authorization", "Bearer " + TOKEN)
      .send(createData);
    
    const userId = createResponse.body.data.id;
    
    // Now delete the user
    const response = await request
      .delete(`/users/${userId}`)
      .set("Authorization", "Bearer " + TOKEN);
    
    console.log(response.body.data);
    expect(response.status).to.be.oneOf([200, 204]);
  });
});

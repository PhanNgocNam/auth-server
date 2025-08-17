const request = require('supertest');
const { app } = require('../src/server');

describe('Authentication and RBAC', () => {
  it('logs in a user and returns a token', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'admin', password: 'password' });
    expect(res.statusCode).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  it('allows access to profile with valid token', async () => {
    const login = await request(app)
      .post('/login')
      .send({ username: 'user', password: 'password' });
    const token = login.body.token;
    const res = await request(app)
      .get('/profile')
      .set('Authorization', `Bearer ${token}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.username).toBe('user');
  });

  it('denies access to admin route for non-admin user', async () => {
    const login = await request(app)
      .post('/login')
      .send({ username: 'user', password: 'password' });
    const token = login.body.token;
    const res = await request(app)
      .get('/admin')
      .set('Authorization', `Bearer ${token}`);
    expect(res.statusCode).toBe(403);
  });

  it('allows admin user to access admin route', async () => {
    const login = await request(app)
      .post('/login')
      .send({ username: 'admin', password: 'password' });
    const token = login.body.token;
    const res = await request(app)
      .get('/admin')
      .set('Authorization', `Bearer ${token}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('Welcome Admin!');
  });
});

const express = require('express')
const app = express()
const fetch = require('cross-fetch');
const jsonwebtoken = require('jsonwebtoken')
const jsdom = require("jsdom");
const jwkToPem = require('jwk-to-pem');
const fs = require('fs')
const jwks = require('./jwks')
const { response, json } = require('express');
const publicKey = fs.readFileSync('./private.key', 'utf8');
const crypto = require("crypto")

const router = express.Router();
app.use(express.json())


const CLIENT_ID = "42ree6438ma07mg36103lr2o1u"
const RESPONSE_TYPE="code"
const REDIRECT_URI="http%3A%2F%2Flocalhost%3A300%2Fauth%2Fcallback"
const SCOPE="openid"
const host = "iupp-login-poc-dev.auth.sa-east-1.amazoncognito.com"


const redirect = "https://iupp-login-poc-dev.auth.sa-east-1.amazoncognito.com/login?response_type=code&client_id=42ree6438ma07mg36103lr2o1u&redirect_uri=http%3A%2F%2Flocalhost%3A300%2Fauth%2Fcallback"

app.get("/get-token-infinite", async(req, res) =>{
  var verifyOptions = {
    expiresIn:  "9999999999999999999y"
   };
  let token = jsonwebtoken.sign({"name": "infinite"}, publicKey, verifyOptions)

  // let verify = jsonwebtoken.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiaW5maW5pdGUiLCJpYXQiOjE2MzcxODA1MjEsImV4cCI6My4xNTU3NmUrMjZ9.w3AiQwyam1q6Tpl8eJwT_R9KokTm01t2dhuoM0849ig", publicKey)

  res.status(200).send({token, publicKey})
})

app.post("/login", async (req, res) => {

    fetch("http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/auth?client_id=myclient&redirect_uri=https%3A%2F%2Fwww.keycloak.org%2Fapp%2F%23url%3Dhttp%3A%2F%2Flocalhost%3A8080%2Fauth%26realm%3Dmyrealm%26client%3Dmyclient&state=60782d3c-f93d-468f-8eb2-9cdef24afba0&response_mode=fragment&response_type=code&scope=openid&nonce=a8152238-a828-487a-8c2c-c47201ccb2ad5", {
      "method": "GET"
    })
    .then(async response => {
      const {username, password} = req.body
      let responseText = await response.text()
      const dom = new jsdom.JSDOM(responseText)
      // console.log(dom)
      // console.log(response)
      let urlPost = dom.window.document.querySelector("form#kc-form-login").attributes.getNamedItem("action").textContent
      console.log(urlPost)
      let cookies = response.headers.get('set-cookie')
      let auth_session_id = cookies.split(";")[0].slice(16)

      console.log("Auth session", auth_session_id)
      // console.log("cookies", cookies)

      let responseLogin = await login(username, password, urlPost, auth_session_id)
      console.log(responseLogin)

      return res.status(200).send(responseLogin)
    })
    .catch(err => {
      console.error(err);
      return res.status(500).send({error: "Erro na autenticação"})
    });
})

async function login(username, password, url, auth_session_id){
  console.log("------------------ Fazendo login")
  let responseLogin = fetch(url, {
    "method": "POST",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": `AUTH_SESSION_ID=${auth_session_id}; AUTH_SESSION_ID_LEGACY=${auth_session_id}; KC_RESTART=`
    },
    "body": `username=${username}&password=${password}`,
    credentials: 'same-origin',
    redirect: 'manual'
  })
  .then(response => {
    let KEYCLOAK_IDENTITY = ""
    let KEYCLOAK_SESSION = ""
    response.headers.get('set-cookie').split(";").forEach(element => {
      if(element.includes("KEYCLOAK_IDENTITY=")){
        KEYCLOAK_IDENTITY = element.split("=")[1]
      }else if(element.includes("KEYCLOAK_SESSION=")){
        KEYCLOAK_SESSION = element.split("=")[1]
      }
    });
    return {
      KEYCLOAK_IDENTITY,
      KEYCLOAK_SESSION
    }
  })
  .catch(err => {
    throw err
  });

  return await responseLogin
}


app.get("/auth/callback", async (req, res) => {
  res.status(200).send(req.query)
})

app.get("/get-claims", async (req, res) => {

  // let response = await fetch("https://cognito-idp.sa-east-1.amazonaws.com/sa-east-1_PpOG4dATs/.well-known/jwks.json", {
  //   "method": "GET"
  // })


  // let jwks = await response.json()

  console.log(jwks)
  const {authorization} = req.headers
  let pem = jwkToPem(jwks.keys[1])
  console.log(pem)
  let payload = jsonwebtoken.verify(authorization, pem, function(err, decoded) {
   console.log(err)
    console.log(decoded)
  })

})

app.get("/login", async (req, res) => {
  try {
    let request = await fetch("https://iupp-login-poc-dev.auth.sa-east-1.amazoncognito.com/login?client_id=niophvho6570142ppl7rhfvif&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&response_type=code&state=ZXlKMWMyVnlVRzl2YkVsa0lqb2lkWE10WldGemRDMHhYMHQ1TUVGc2RYazNVaUlzSW5CeWIzWnBaR1Z5VG1GdFpTSTZJbWwwWVhVaUxDSmpiR2xsYm5SSlpDSTZJall5Ym5JM1pqQXlZMkp3WVRrNU5uRnBPV052Y3pjMFlYVmtJaXdpY21Wa2FYSmxZM1JWVWtraU9pSm9kSFJ3Y3pvdkwybDFjSEF0Y1dFdWQyVmljSEpsYldsdmN5NWthV2RwZEdGc0wyRjFkR2d2WTJGc2JHSmhZMnNpTENKeVpYTndiMjV6WlZSNWNHVWlPaUowYjJ0bGJpSXNJbkJ5YjNacFpHVnlWSGx3WlNJNklrOUpSRU1pTENKelkyOXdaWE1pT2xzaVlYZHpMbU52WjI1cGRHOHVjMmxuYm1sdUxuVnpaWEl1WVdSdGFXNGlMQ0psYldGcGJDSXNJbTl3Wlc1cFpDSXNJbkJ5YjJacGJHVWlMQ0ozWldKd2NtVnRhVzl6TG1OaGJYQmhhV2R1Y3k4M01qVTBNU0pkTENKemRHRjBaU0k2Ym5Wc2JDd2lZMjlrWlVOb1lXeHNaVzVuWlNJNmJuVnNiQ3dpWTI5a1pVTm9ZV3hzWlc1blpVMWxkR2h2WkNJNmJuVnNiQ3dpYm05dVkyVWlPaUpGVm0welozcEZXRzlFUzJOSlZ6WTVlREE1WVhSVVIwbENiRUZqVEV0ZlQyNXJUVzlMUnpaaGFuaHlUREpqV0VWTGIwMTBUMWgyZFc5MVVqaFBRMWRWYTJOeFVEZGtSMUZ2U1hCSkxWTlVaM2s0YjFJMk4ySkRTSE5XWVc1a2VHNHpkRXB2ZEVOalJWTktZVmx1U25vdGFTMDNlRXhuUm5SV2RFSXplWE5zT0hCSlZHNWxPR2hQTW5KUFJWaDZXV05CY0hOelVuWkxiR1JtVGkxRVp6ZHNYMFJaYVhnell6QkxWVkVpTENKelpYSjJaWEpJYjNOMFVHOXlkQ0k2SW14MGJTMXlZV2R1WVhKdmF5MTBaVzVoYm5SekxYRmhMVGN5TlRReExtRjFkR2d1ZFhNdFpXRnpkQzB4TG1GdFlYcHZibU52WjI1cGRHOHVZMjl0SWl3aVkzSmxZWFJwYjI1VWFXMWxVMlZqYjI1a2N5STZNVFl6TWprMU9UZzBOU3dpYzJWemMybHZiaUk2Ym5Wc2JDd2lkWE5sY2tGMGRISnBZblYwWlhNaU9tNTFiR3dzSW5OMFlYUmxSbTl5VEdsdWEybHVaMU5sYzNOcGIyNGlPbVpoYkhObGZRPT06Mk5PM280dHVDMkhJUFF6MjlGVlNMVGFoRzN3R1oyZmtpTS9lZTJEcm8zUT06Mw%3D%3D", {
      method: "POST",
      headers: {
        "Host": "iupp-login-poc-dev.auth.sa-east-1.amazoncognito.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "XSRF-TOKEN=a35d52e5-1d6c-480e-a64a-04a730cbf64a;cognito-fl=\"W10=\"",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "origin": "https://iupp-login-poc-dev.auth.sa-east-1.amazoncognito.com"
      },
      body: "username=46402770133&password=LDZMFUfqApWtwTONngZrtnOYYqpeLdNhByMKOgIAPNGGUaqVSrioQcHRKCtQbPWzolrNhuWjTthVAzPFQqLspIavKBDJqJKdMnzhXFEINGWChGKwyzmgdwrWPYpjgTxrveAdfpJZjVzjJENDStpuLmjDtzGQFMZRKFkXwHATrElbtLPJsIFfGEYFfAiMrGkZIHiCykdkcuQguLuJvauZxivlhDnxtjpxhdqkNsXmGHPBXJBCtZClXixdAaHTMHEE&_csrf=a35d52e5-1d6c-480e-a64a-04a730cbf64a",
      credentials: 'same-origin',
      redirect: 'manual'
    })  

    console.log(request.headers)
    // let response = await request.json()
    // console.log("Headers:",request.headers)
    return res.status(200).send(request.Headers)
  } catch (error) {
    console.log(error)
    return res.status(500).send(error)
  }
})

app.post("/login2", async (req, res) => {

  console.log(req.headers)

  var id = crypto.randomBytes(20).toString('hex');

  return res.send({Token: `${id}`, ExpirationDate: 15000})

})

app.get("/order", async (req, res) => {

  console.log("login3")
  console.log(req.headers)

  return res.send({Token: req.headers["authorization"] + "", ExpirationDate: 15000})

})

app.use(router)
app.listen(3000)
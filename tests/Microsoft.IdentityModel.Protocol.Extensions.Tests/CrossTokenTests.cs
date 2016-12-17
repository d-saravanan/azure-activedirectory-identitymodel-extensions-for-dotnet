//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Security.Claims;

using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;
using SMSamlTokenHandler = System.IdentityModel.Tokens.SamlSecurityTokenHandler;
using SMSaml2TokenHandler = System.IdentityModel.Tokens.Saml2SecurityTokenHandler;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// The purpose of these tests are to ensure that Saml, Saml2 and Jwt handling 
    /// results in the same exceptions, claims etc.
    /// </summary>
    [TestClass]
    public class CrossTokenTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "ADEFAC1A-07AC-4A0E-B49E-F7FF39CC2DD5")]
        [Description("Tests: Validates tokens")]
        public void CrossToken_ValidateToken()
        {
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            IMSaml2TokenHandler imSaml2Handler = new IMSaml2TokenHandler();
            IMSamlTokenHandler imSamlHandler = new IMSamlTokenHandler();
            SMSaml2TokenHandler smSaml2Handler = new SMSaml2TokenHandler();
            SMSamlTokenHandler smSamlHandler = new SMSamlTokenHandler();

            JwtSecurityTokenHandler.InboundClaimFilter.Add("aud");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("exp");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iat");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iss");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("nbf");

            SecurityKey x509SecurityKey = new X509SecurityKey(KeyingMaterial.DefaultCert_2048);
            SigningCredentials signingCredentials = new SigningCredentials(x509SecurityKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                AppliesToAddress = IdentityUtilities.DefaultAudience,
                SigningCredentials = signingCredentials,
                Subject = IdentityUtilities.DefaultClaimsIdentity,
                TokenIssuerName = IdentityUtilities.DefaultIssuer,
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
            };

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                AuthenticationType = IdentityUtilities.DefaultAuthenticationType,
                IssuerSigningKey = x509SecurityKey,
                ValidAudience = IdentityUtilities.DefaultAudience,
                ValidIssuer = IdentityUtilities.DefaultIssuer,
                ValidateIssuerSigningKey = true
            };

            // Test ValidateIssuerSigningKey = true, validationParameters.CertificateValidator == null
            string jwtTokenTest = IdentityUtilities.CreateJwtToken(descriptor, jwtHandler);
            ClaimsPrincipal jwtPrincipalTest = ValidateToken(jwtTokenTest, validationParameters, jwtHandler, ExpectedException.SecurityTokenValidationException("IDX10232:"));

            string nullIssuerJwtToken = IdentityUtilities.CreateJwtToken(IdentityUtilities.NullIssuerAsymmetricSecurityTokenDescriptor, jwtHandler);
            string jwtToken = IdentityUtilities.CreateJwtToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, jwtHandler);

            // Test ValidateIssuerSigningKey = true, signingkey is not X509SecurityKey
            validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.ValidateIssuerSigningKey = true;
            jwtPrincipalTest = ValidateToken(jwtToken, validationParameters, jwtHandler, ExpectedException.SecurityTokenValidationException("IDX11009:"));

            // saml tokens created using Microsoft.IdentityModel.Extensions
            string imSaml2Token = IdentityUtilities.CreateSaml2Token(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, imSaml2Handler);
            string imSamlToken = IdentityUtilities.CreateSamlToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, imSamlHandler);

            // saml tokens created using System.IdentityModel.Tokens
            string smSaml2Token = IdentityUtilities.CreateSaml2Token(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, smSaml2Handler);
            string smSamlToken = IdentityUtilities.CreateSamlToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor, smSamlHandler);

            ClaimsPrincipal jwtPrincipal = ValidateToken(jwtToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, jwtHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal jwtPrincipal2 = ValidateToken(nullIssuerJwtToken, IdentityUtilities.GetNullIssuerAsymmetricTokenValidationParameters(false), jwtHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal jwtPrincipal3 = ValidateToken(nullIssuerJwtToken, IdentityUtilities.GetNullIssuerAsymmetricTokenValidationParameters(true), jwtHandler, ExpectedException.SecurityTokenInvalidIssuerException("IDX10211:"));

            jwtHandler.SetDefaultTimesOnTokenCreation = false;
            string nullLifetimeJwtToken = IdentityUtilities.CreateJwtToken(IdentityUtilities.NullLifetimeAsymmetricSecurityTokenDescriptor, jwtHandler);
            // Test SetDefaultTimesOnTokenCreation = false,  RequireExpirationTime = false;
            ClaimsPrincipal jwtPrincipal4 = ValidateToken(nullLifetimeJwtToken, IdentityUtilities.NullLifetimeAsymmetricTokenValidationParameters, jwtHandler, ExpectedException.NoExceptionExpected);
            TokenValidationParameters nullLifetimeAsymmetricTokenValidationParameters = IdentityUtilities.NullLifetimeAsymmetricTokenValidationParameters;
            nullLifetimeAsymmetricTokenValidationParameters.RequireExpirationTime = true;
            // Test SetDefaultTimesOnTokenCreation = false,  RequireExpirationTime = true;
            ClaimsPrincipal jwtPrincipal5 = ValidateToken(nullLifetimeJwtToken, nullLifetimeAsymmetricTokenValidationParameters, jwtHandler, ExpectedException.SecurityTokenNoExpirationException("IDX10225:"));
            jwtHandler.SetDefaultTimesOnTokenCreation = true;

            ClaimsPrincipal imSaml2Principal = ValidateToken(imSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSaml2Handler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal imSamlPrincipal = ValidateToken(imSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSamlHandler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal smSaml2Principal = ValidateToken(smSaml2Token, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSaml2Handler, ExpectedException.NoExceptionExpected);
            ClaimsPrincipal smSamlPrincipal = ValidateToken(smSamlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, imSamlHandler, ExpectedException.NoExceptionExpected);

            Assert.AreEqual(jwtPrincipal2.FindFirst(ClaimTypes.Country).Issuer, ClaimsIdentity.DefaultIssuer);
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(imSamlPrincipal,  imSaml2Principal, new CompareContext { IgnoreSubject = true }));
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(smSamlPrincipal,  imSaml2Principal, new CompareContext { IgnoreSubject = true }));
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(smSaml2Principal, imSaml2Principal, new CompareContext { IgnoreSubject = true }));

            // false = ignore type of objects, we expect all objects in the principal to be of same type (no derived types)
            // true = ignore subject, claims have a backpointer to their ClaimsIdentity.  Most of the time this will be different as we are comparing two different ClaimsIdentities.
            // true = ignore properties of claims, any mapped claims short to long for JWT's will have a property that represents the short type.
            Assert.IsTrue(IdentityComparer.AreEqual<ClaimsPrincipal>(jwtPrincipal, imSaml2Principal, new CompareContext{IgnoreType = false, IgnoreSubject = true, IgnoreProperties=true}));

            JwtSecurityTokenHandler.InboundClaimFilter.Clear();
        }

        private ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, ISecurityTokenValidator tokenValidator, ExpectedException expectedException)
        {
            ClaimsPrincipal principal = null;
            try
            {
                SecurityToken validatedToken;
                principal = tokenValidator.ValidateToken(securityToken, validationParameters, out validatedToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return principal;
        }


        [TestMethod]
        [TestProperty("TestCaseID", "c49e0f0a-decb-48a9-8695-25999ecfac59")]
        [Description("Tests: Validates Signatures")]
        public void CrossToken_ValidateSignature()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "fbed514b-d3ed-49ef-92ac-40a175cf6c6d")]
        [Description("Tests: Validate Audience")]
        public void CrossToken_ValidateAudience()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "a4d35cae-5312-4110-b2c0-325fbce4c085")]
        [Description("Tests: Validate Issuer")]
        public void CrossToken_ValidateIssuer()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }

        [TestMethod]
        [TestProperty("TestCaseID", "3f5f3a1f-49cc-495a-8198-7c321e870294")]
        [Description("Tests: ValidateLifetime")]
        public void CrossToken_ValidateLifetime()
        {
            // TODO - when finalizing OM, ensure jwt, saml1 and saml2 work the same
        }
    }
}
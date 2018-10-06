/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.util.password;


import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.framework.TestCase;


public class ConfigurablePasswordEncryptorTest extends TestCase {

    private final static Provider SCPROVIDER = new BouncyCastleProvider();
    static {
    	Security.addProvider(SCPROVIDER);
    }
    
    public void testDigest() throws Exception {

        String password = "This is a Password";
        
        ConfigurablePasswordEncryptor passwordEncryptor = new ConfigurablePasswordEncryptor();
        passwordEncryptor.setAlgorithm("WHIRLPOOL");
        passwordEncryptor.setProvider(SCPROVIDER);
        
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        assertNotNull(encryptedPassword.getBytes(StandardCharsets.UTF_8));
        
        for (int i = 0; i < 10; i++) {
            assertTrue(passwordEncryptor.checkPassword(password, encryptedPassword));
        }
        
        String password2 = "This is a  Password";
        for (int i = 0; i < 10; i++) {
            assertFalse(passwordEncryptor.checkPassword(password2, encryptedPassword));
        }

        ConfigurablePasswordEncryptor digester2 = new ConfigurablePasswordEncryptor();
        digester2.setAlgorithm("WHIRLPOOL");
        digester2.setProviderName(SCPROVIDER.getName());
        
        for (int i = 0; i < 10; i++) {
            assertTrue(digester2.checkPassword(password, encryptedPassword));
        }
        
        for (int i = 0; i < 10; i++) {
            assertFalse(
                    passwordEncryptor.encryptPassword(password).equals(
                            passwordEncryptor.encryptPassword(password)));
        }
        
        StrongPasswordEncryptor digester3 = new StrongPasswordEncryptor();
        encryptedPassword = digester3.encryptPassword(password);
        
        for (int i = 0; i < 10; i++) {
            assertTrue(digester3.checkPassword(password, encryptedPassword));
        }
        
    }

    
}

package com.iluwatar.security.demo;

import java.util.Arrays;

/**
 * SECURITY HOTSPOT DEMONSTRATION
 * 
 * Objective: Identify and resolve security vulnerabilities.
 * Case Study: String vs char[] for password storage
 * 
 * Scenario: A Java project uses String for passwords. SonarQube flags this as a security hotspot.
 */

// ❌ INSECURE - Before Fix
public class InsecurePasswordHandling {
    
    public static void main(String[] args) {
        // PROBLEM 1: Password stored as String
        String password = "mysecretpassword123";
        
        // What happens:
        // 1. String is immutable - once created, stays in memory
        // 2. Garbage Collector doesn't know it's sensitive
        // 3. Can be visible in heap dumps
        // 4. May be optimized and cached by JVM
        // 5. String intern pool holds reference permanently
        
        authenticateUser("john@example.com", password);
        
        // PROBLEM 2: Even after function ends, password is still in memory
        // Java's GC might not collect it immediately
        // Attacker could dump heap and extract password
    }
    
    static void authenticateUser(String email, String password) {
        // PROBLEM 3: Password might be logged accidentally
        System.out.println("User: " + email);
        // Never do this! System.out.println("Password: " + password);
        
        // PROBLEM 4: Comparison still holds string in memory
        if ("correctpassword".equals(password)) {
            System.out.println("Authenticated");
        }
        // Password string persists beyond authentication
    }
}

// ✅ SECURE - After Fix
public class SecurePasswordHandling {
    
    public static void main(String[] args) {
        // SOLUTION 1: Use char[] instead of String
        char[] password = "mysecretpassword123".toCharArray();
        
        // Benefits:
        // 1. char[] is mutable
        // 2. We can explicitly clear it: Arrays.fill(password, '\0')
        // 3. GC can clean it up immediately
        // 4. Won't be interned or cached
        // 5. More control over memory lifecycle
        
        try {
            authenticateUser("john@example.com", password);
        } finally {
            // CRITICAL: Always clear the password from memory
            Arrays.fill(password, '\0');  // Overwrite with zeros
        }
        
        // Now password is securely cleared
        // Even if attacker dumps heap, only zeros are visible
    }
    
    static void authenticateUser(String email, char[] password) {
        // SECURE: Don't convert back to String
        if (password != null && password.length > 0) {
            // Secure comparison
            char[] correctPassword = "correctpassword".toCharArray();
            boolean isValid = Arrays.equals(password, correctPassword);
            
            // Don't forget to clear the reference password too!
            Arrays.fill(correctPassword, '\0');
            
            if (isValid) {
                System.out.println("User " + email + " authenticated successfully");
            }
        }
        
        // Password is still in memory here, but NOT persisted
        // Caller will clear it in finally block
    }
}

// ========================================
// KEY DIFFERENCES EXPLAINED
// ========================================

/**
 * WHY STRING IS INSECURE FOR PASSWORDS:
 * 
 * ❌ String password = "secret";
 * 
 * Problems:
 * 1. IMMUTABILITY: Cannot be modified or cleared from memory
 *    - Once created, exists until GC collects it
 *    - JVM may cache it in string intern pool
 * 
 * 2. MEMORY PERSISTENCE: Stays in heap memory indefinitely
 *    - Visible in heap dumps
 *    - Not eligible for cleanup until entire String object is GC'd
 *    - May be paged to disk in memory swaps
 * 
 * 3. LOGGING RISK: Accidentally logged to files/logs
 *    - toString() will expose password
 *    - Exception stack traces might include it
 * 
 * 4. SERIALIZATION: Can be serialized/stored in JVM memory
 *    - Reflected in bytecode
 *    - Can be extracted from bytecode
 * 
 * ========================================
 * 
 * WHY CHAR[] IS SECURE FOR PASSWORDS:
 * 
 * ✅ char[] password = "secret".toCharArray();
 * 
 * Benefits:
 * 1. MUTABILITY: Can be explicitly cleared
 *    - Arrays.fill(password, '\0') overwrites memory with zeros
 *    - Can happen immediately after use
 *    - No GC delays
 * 
 * 2. MEMORY CONTROL: Direct control over lifetime
 *    - Can clear before passing to other methods
 *    - No implicit caching
 *    - No string intern pool issues
 * 
 * 3. LOGGING SAFE: Arrays.toString() not recommended
 *    - Developer won't accidentally log it
 *    - No default Object.toString() disclosure
 * 
 * 4. SECURITY APIs: Required by many security libraries
 *    - javax.security.auth.Destroyable interface
 *    - PasswordAuthentication expects char[]
 *    - Java best practices recommend char[]
 */

// ========================================
// SONARQUBE CONFIGURATION
// ========================================

/**
 * To make SonarQube flag String password variables as critical:
 * 
 * File: sonar-project.properties or pom.xml
 * 
 * Add rule override:
 * sonar.java.rules.hotspots.vulnerabilities=\
 *   java:S2068,\
 *   java:S6418
 * 
 * Custom rule to flag password strings:
 * 
 * <rule>
 *   <key>password-string-usage</key>
 *   <name>Do not use String for passwords</name>
 *   <type>SECURITY_HOTSPOT</type>
 *   <severity>CRITICAL</severity>
 *   <pattern>
 *     <match>
 *       <type>FIELD_DECLARATION</type>
 *       <fieldType>String</fieldType>
 *       <fieldName>*password*</fieldName>
 *     </match>
 *   </pattern>
 * </rule>
 */

// ========================================
// BEFORE/AFTER COMPARISON
// ========================================

class BeforeAfterPasswordDemo {
    
    // BEFORE: String password vulnerability
    static class UserBefore {
        private String username;
        private String password;  // ❌ SECURITY HOTSPOT
        
        public UserBefore(String username, String password) {
            this.username = username;
            this.password = password;  // Stored as String (insecure)
        }
        
        public boolean authenticate(String inputPassword) {
            return inputPassword.equals(password);  // Password vs String comparison
            // password String remains in memory
        }
    }
    
    // AFTER: char[] password security fix
    static class UserAfter {
        private String username;
        private char[] password;  // ✅ SECURE
        
        public UserAfter(String username, String password) {
            this.username = username;
            // Convert to char[] immediately
            this.password = password != null ? password.toCharArray() : null;
        }
        
        public boolean authenticate(String inputPassword) {
            if (password == null) {
                return false;
            }
            // Convert input to char[] for comparison
            char[] inputPasswordChars = inputPassword.toCharArray();
            boolean result = Arrays.equals(inputPasswordChars, password);
            
            // IMPORTANT: Clear the temporary char[] from memory
            Arrays.fill(inputPasswordChars, '\0');
            
            return result;
        }
        
        /**
         * CRITICAL: Must be called after authentication is complete
         * Always use try-finally to guarantee cleanup
         */
        public void destroy() {
            if (password != null) {
                Arrays.fill(password, '\0');  // Overwrite with zeros
                password = null;  // Clear reference
            }
        }
    }
    
    public static void main(String[] args) {
        System.out.println("=== SECURITY HOTSPOT DEMO ===\n");
        
        // BEFORE: Insecure
        System.out.println("BEFORE (Insecure):");
        UserBefore userBefore = new UserBefore("alice", "password123");
        boolean authBefore = userBefore.authenticate("password123");
        System.out.println("  - Authenticated: " + authBefore);
        System.out.println("  - Risk: Password string persists in memory");
        System.out.println("  - SonarQube Flag: SECURITY HOTSPOT\n");
        
        // AFTER: Secure
        System.out.println("AFTER (Secure with char[]):");
        UserAfter userAfter = new UserAfter("alice", "password123");
        try {
            boolean authAfter = userAfter.authenticate("password123");
            System.out.println("  - Authenticated: " + authAfter);
            System.out.println("  - Protected: Password cleared from memory after use");
            System.out.println("  - SonarQube Flag: ✅ RESOLVED");
        } finally {
            userAfter.destroy();  // Explicitly clear password
            System.out.println("  - Cleanup: Password memory cleared");
        }
    }
}

// ========================================
// BEST PRACTICES SUMMARY
// ========================================

/**
 * ✅ DO:
 * - Use char[] for all password/sensitive data storage
 * - Call Arrays.fill(password, '\0') after use
 * - Use try-finally to guarantee cleanup
 * - Use javax.security.auth.Destroyable interface
 * - Store passwords in secure vaults (HashiCorp Vault, AWS Secrets Manager)
 * - Use environment variables for credentials (never hardcode)
 * - Implement password validation libraries (bcrypt, argon2)
 * 
 * ❌ DON'T:
 * - Store passwords as String variables
 * - Log passwords or sensitive data
 * - Hardcode credentials in source code
 * - Rely on JVM GC to clear sensitive data
 * - Serialize sensitive data
 * - Use String.equals() for password comparison (timing attacks)
 * - Store passwords in plain text anywhere
 */

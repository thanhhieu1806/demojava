# Fix 401 Register/Login on MobaXterm Deploy

## Status: 🚀 In Progress

### [x] 0. Created TODO.md & confirmed plan

### [x] 1. Add logging to InMemoryUserService.java (used standard logging, fixed syntax)

### [x] 2. Add HealthController & logging config

### [x] 3. Add AuthController logging & fixed all logging without lombok

### [ ] 4. Local test

### [ ] 5. Deploy & verify
   - Log @PostConstruct initDefaultUsers
   - Log loadUserByUsername
   - Log registerUser

### [ ] 2. Add logging to AuthController.java
   - Log authentication attempts & failures

### [ ] 3. Update application.properties
   - Enable DEBUG logging
   - H2 tweaks for Linux deploy

### [ ] 4. Create HealthController.java
   - /api/health endpoint to check DB/users

### [ ] 5. Test locally
   - mvn spring-boot:run
   - Test register/login

### [ ] 6. Build & deploy instructions
   - mvn package
   - Server steps: chmod, curl tests

### [ ] 7. Verify fix ✅
   - No more 401 on deploy


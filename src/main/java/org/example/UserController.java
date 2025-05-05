//package org.example;
//
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//import org.springframework.web.server.ResponseStatusException;
//
//@RestController
//@RequestMapping("/api/users")
//public class UserController {
//    private final UserRepository repo;
//
//    @PutMapping("/{username}/public-key")
//    public ResponseEntity<Void> setKey(
//            @PathVariable String username,
//            @RequestBody String publicKey) {
//        User u = repo.findByUsername(username)
//                .orElseThrow(() -> new ResponseStatusException(404));
//        u.setPublicKey(publicKey);
//        repo.save(u);
//        return ResponseEntity.ok().build();
//    }
//
//    @GetMapping("/{username}/public-key")
//    public ResponseEntity<String> getKey(@PathVariable String username) {
//        return repo.findByUsername(username)
//                .map(User::getPublicKey)
//                .filter(pk -> !pk.isBlank())
//                .map(pk -> ResponseEntity.ok(pk))
//                .orElse(ResponseEntity.noContent().build());
//    }
//}
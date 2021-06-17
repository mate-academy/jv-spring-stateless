package mate.academy.service.impl;

import java.util.List;
import java.util.Optional;
import mate.academy.dao.UserDao;
import mate.academy.model.User;
import mate.academy.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserServiceImpl implements UserService {
    private final UserDao userDao;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserDao userDao, PasswordEncoder passwordEncoder) {
        this.userDao = userDao;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User save(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userDao.save(user);
    }

    @Override
    public User findById(Long id) {
        return userDao.findById(id).get();
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userDao.findByEmail(email);
    }

    @Override
    public void delete(Long id) {
        userDao.delete(id);
    }

    @Override
    public List<User> findAll() {
        return userDao.findAll();
    }
}

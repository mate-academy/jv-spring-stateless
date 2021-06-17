package mate.academy.service.impl;

import java.util.List;
import mate.academy.dao.ProductDao;
import mate.academy.model.Product;
import mate.academy.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ProductServiceImpl implements ProductService {
    private final ProductDao productDao;

    @Autowired
    public ProductServiceImpl(ProductDao productDao) {
        this.productDao = productDao;
    }

    @Override
    public Product save(Product product) {
        return productDao.save(product);
    }

    @Override
    public List<Product> findAll() {
        return productDao.findAll();
    }

    @Override
    public void delete(Long id) {
        productDao.delete(id);
    }
}

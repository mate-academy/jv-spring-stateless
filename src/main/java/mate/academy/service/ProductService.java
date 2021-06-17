package mate.academy.service;

import java.util.List;
import mate.academy.model.Product;

public interface ProductService {
    Product save(Product product);

    List<Product> findAll();

    void delete(Long id);
}

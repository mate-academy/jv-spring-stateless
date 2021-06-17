package mate.academy.dao;

import java.util.List;
import mate.academy.model.Product;

public interface ProductDao {
    Product save(Product product);

    List<Product> findAll();

    void delete(Long id);
}

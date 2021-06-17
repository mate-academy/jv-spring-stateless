package mate.academy.dao.impl;

import mate.academy.dao.ProductDao;
import mate.academy.model.Product;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class ProductDaoImpl extends AbstractDao<Product, Long> implements ProductDao {
    @Autowired
    public ProductDaoImpl(SessionFactory sessionFactory) {
        super(sessionFactory, Product.class);
    }
}

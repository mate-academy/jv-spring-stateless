package mate.academy.service.mapper;

import mate.academy.model.Product;
import mate.academy.model.dto.ProductRequestDto;
import mate.academy.model.dto.ProductResponseDto;
import org.springframework.stereotype.Component;

@Component
public class ProductDtoMapper {
    public Product mapToModel(ProductRequestDto requestDto) {
        Product product = new Product();
        product.setPrice(requestDto.getPrice());
        product.setName(requestDto.getName());
        return product;
    }

    public ProductResponseDto mapToDto(Product product) {
        ProductResponseDto responseDto = new ProductResponseDto();
        responseDto.setId(product.getId());
        responseDto.setName(product.getName());
        responseDto.setPrice(product.getPrice());
        return responseDto;
    }
}

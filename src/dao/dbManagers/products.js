import productsModel from "../models/products.model.js"

export default class Products {
    constructor() {
        // console.log(`Working products with Database persistence in mongodb`)
    }

    getAll = async (limit = 8, page = 1, queryOptions = {}, sort = '') => {
        try {
            // Calcular el índice de inicio para paginación
            const startIndex = (page - 1) * limit;
            let productsQuery = productsModel.find(queryOptions);

            if (sort === 'asc') {
                productsQuery = productsQuery.sort({ price: 1 }); // Ordenar por precio ascendente
            } else if (sort === 'desc') {
                productsQuery = productsQuery.sort({ price: -1 }); // Ordenar por precio descendente
            }

            // Calcular información de paginación
            const products = await productsQuery.skip(startIndex).limit(limit).exec();
            const totalProducts = await productsModel.countDocuments(queryOptions);
            const totalPages = Math.ceil(totalProducts / limit);
            const hasNextPage = page < totalPages;
            const hasPrevPage = page > 1;

            return {
                products,
                totalPages,
                prevPage: hasPrevPage ? page - 1 : null,
                nextPage: hasNextPage ? page + 1 : null,
                page,
                hasPrevPage,
                hasNextPage,
            };
        } catch (error) {
            throw error;
        }
    }
}

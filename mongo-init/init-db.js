// Script de inicialización para MongoDB
// Este script se ejecuta automáticamente cuando se crea el contenedor

// Cambiar a la base de datos del proyecto
db = db.getSiblingDB('vulnerability_scanner');

// Crear colección para resultados de scans
db.createCollection('scan_results');

// Crear índices para mejorar el rendimiento
db.scan_results.createIndex({ "scan_type": 1 });
db.scan_results.createIndex({ "timestamp": -1 });
db.scan_results.createIndex({ "scan_type": 1, "timestamp": -1 });

// Crear índices para búsquedas específicas
db.scan_results.createIndex({ "result_data.pdf_path": 1 });
db.scan_results.createIndex({ "result_data.source_code_path": 1 });
db.scan_results.createIndex({ "result_data.target_url": 1 });

// Insertar documento de ejemplo para verificar la configuración
db.scan_results.insertOne({
    scan_type: "system_init",
    timestamp: new Date(),
    result_data: {
        message: "Base de datos inicializada correctamente",
        version: "1.0.0"
    },
    metadata: {
        init_script: "mongo-init/init-db.js"
    }
});

print('Base de datos vulnerability_scanner inicializada correctamente');
print('Colecciones creadas: scan_results');
print('Índices creados para optimizar consultas');
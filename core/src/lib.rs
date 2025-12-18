use pyo3::prelude::*;

mod entropy;
mod hilbert;

#[pyfunction]
#[pyo3(signature = (data, window_size=16))]
fn calculate_entropy(data: &[u8], window_size: usize) -> Vec<f64> {
    entropy::calculate_entropy_internal(data, window_size)
}

#[pyfunction]
fn generate_hilbert_coords(order: u32) -> Vec<(i32, i32)> {
    hilbert::generate_hilbert_internal(order)
}

#[pyfunction]
fn get_hilbert_size(order: u32) -> u32 {
    hilbert::get_hilbert_size(order)
}

#[pymodule]
fn binartia_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(generate_hilbert_coords, m)?)?;
    m.add_function(wrap_pyfunction!(get_hilbert_size, m)?)?;
    Ok(())
}

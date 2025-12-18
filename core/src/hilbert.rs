// generate Hilbert curve coords for a given order.
pub fn generate_hilbert_internal(order: u32) -> Vec<(i32, i32)> {
    if order == 0 {
        return vec![(0, 0)];
    }

    let n = 1u32 << order;
    let total_points = n * n;

    (0..total_points).map(|d| d_to_xy(n, d)).collect()
}

// convert Hilbert curve index to (x, y) coords using iterative algorithm.
#[inline]
fn d_to_xy(n: u32, d: u32) -> (i32, i32) {
    let mut x = 0u32;
    let mut y = 0u32;
    let mut s = 1u32;
    let mut t = d;

    while s < n {
        let rx = 1 & (t / 2);
        let ry = 1 & (t ^ rx);
        if ry == 0 {
            if rx == 1 {
                x = s.wrapping_sub(1).wrapping_sub(x);
                y = s.wrapping_sub(1).wrapping_sub(y);
            }
            std::mem::swap(&mut x, &mut y);
        }
        x += s * rx;
        y += s * ry;
        t /= 4;
        s *= 2;
    }
    (x as i32, y as i32)
}

#[inline]
pub fn get_hilbert_size(order: u32) -> u32 {
    1 << order
}

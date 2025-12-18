use rayon::prelude::*;

// pre-computed log2 lookup table (avoids expensive log2 calls)
static LOG2_TABLE: std::sync::LazyLock<[f64; 257]> = std::sync::LazyLock::new(|| {
    let mut table = [0.0f64; 257];
    for i in 1..257 {
        table[i] = (i as f64).log2();
    }
    table
});

#[inline]
fn entropy_from_counts_fast(counts: &[u32; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }

    let n = total as f64;
    let log2_n = n.log2();
    let mut sum_count_log = 0.0f64;

    for &count in counts {
        if count > 0 {
            let c = count as usize;
            let log2_c = if c < 257 {
                LOG2_TABLE[c]
            } else {
                (c as f64).log2()
            };
            sum_count_log += count as f64 * log2_c;
        }
    }
    (log2_n - sum_count_log / n).max(0.0)
}

// calculate local entropy using sliding window with O(n) complexity.
pub fn calculate_entropy_internal(data: &[u8], window_size: usize) -> Vec<f64> {
    if data.is_empty() {
        return Vec::new();
    }

    let len = data.len();
    let half_window = window_size / 2;

    if len > 50_000 {
        return calculate_entropy_chunked_parallel(data, window_size);
    }
    calculate_entropy_sequential(data, half_window)
}

fn calculate_entropy_sequential(data: &[u8], half_window: usize) -> Vec<f64> {
    let len = data.len();
    let mut entropy_values = Vec::with_capacity(len);
    let mut counts = [0u32; 256];
    let mut window_len = 0usize;

    let first_end = (half_window + 1).min(len);
    for &byte in &data[..first_end] {
        counts[byte as usize] += 1;
        window_len += 1;
    }
    entropy_values.push(entropy_from_counts_fast(&counts, window_len));

    for i in 1..len {
        let new_end = (i + half_window + 1).min(len);
        let prev_end = (i + half_window).min(len);
        if i > half_window {
            let remove_idx = i - half_window - 1;
            counts[data[remove_idx] as usize] -= 1;
            window_len -= 1;
        }
        if new_end > prev_end {
            counts[data[new_end - 1] as usize] += 1;
            window_len += 1;
        }
        entropy_values.push(entropy_from_counts_fast(&counts, window_len));
    }
    normalize_entropy(&mut entropy_values);
    entropy_values
}

fn calculate_entropy_chunked_parallel(data: &[u8], window_size: usize) -> Vec<f64> {
    let len = data.len();
    let half_window = window_size / 2;
    let num_threads = rayon::current_num_threads();
    let chunk_size = (len / num_threads).max(10_000);

    let chunks: Vec<_> = (0..len)
        .step_by(chunk_size)
        .map(|start| (start, (start + chunk_size).min(len)))
        .collect();

    let chunk_results: Vec<Vec<f64>> = chunks
        .par_iter()
        .map(|&(chunk_start, chunk_end)| {
            let mut results = Vec::with_capacity(chunk_end - chunk_start);
            let mut counts = [0u32; 256];
            for i in chunk_start..chunk_end {
                let win_start = i.saturating_sub(half_window);
                let win_end = (i + half_window + 1).min(len);
                if i == chunk_start {
                    for &byte in &data[win_start..win_end] {
                        counts[byte as usize] += 1;
                    }
                } else {
                    let prev_start = (i - 1).saturating_sub(half_window);
                    let prev_end = (i + half_window).min(len);

                    if win_start > prev_start {
                        for &byte in &data[prev_start..win_start] {
                            counts[byte as usize] -= 1;
                        }
                    }
                    if win_end > prev_end {
                        for &byte in &data[prev_end..win_end] {
                            counts[byte as usize] += 1;
                        }
                    }
                }
                results.push(entropy_from_counts_fast(&counts, win_end - win_start));
            }
            results
        })
        .collect();

    let mut entropy_values: Vec<f64> = chunk_results.into_iter().flatten().collect();
    normalize_entropy(&mut entropy_values);
    entropy_values
}

#[inline]
fn normalize_entropy(values: &mut [f64]) {
    let max = values.iter().cloned().fold(0.0f64, f64::max);
    if max > 0.0 {
        values.iter_mut().for_each(|v| *v /= max);
    }
}

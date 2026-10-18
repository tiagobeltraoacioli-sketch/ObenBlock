//! A bounded ring of recent jobs per connection, keyed by `job_id`, so late
//! or ntime-rolled submits against a slightly older job of the same tip
//! still validate.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::job::ObbJob;

pub struct JobStore {
    jobs: VecDeque<Arc<ObbJob>>,
    cap: usize,
}

impl JobStore {
    /// A store keeping the last `cap` jobs.
    pub fn new(cap: usize) -> Self {
        JobStore { jobs: VecDeque::with_capacity(cap.max(1)), cap: cap.max(1) }
    }

    /// Insert a job. With `clean_jobs`, jobs built on other parents are
    /// dropped (their blocks could only be orphan-prone siblings of the new
    /// tip); jobs on the same parents are kept, so a re-template on an
    /// unchanged tip never turns in-flight shares stale.
    pub fn insert(&mut self, job: Arc<ObbJob>, clean_jobs: bool) {
        if clean_jobs {
            self.jobs.retain(|j| j.parents_commitment == job.parents_commitment);
        }
        if let Some(pos) = self.jobs.iter().position(|j| j.job_id == job.job_id) {
            self.jobs.remove(pos);
        }
        self.jobs.push_back(job);
        while self.jobs.len() > self.cap {
            self.jobs.pop_front();
        }
    }

    pub fn get(&self, job_id: &str) -> Option<&Arc<ObbJob>> {
        self.jobs.iter().find(|j| j.job_id == job_id)
    }

    pub fn latest(&self) -> Option<&Arc<ObbJob>> {
        self.jobs.back()
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::tests::{template_from_vector, vector_extranonce};

    fn job(id: &str, parents_byte: u8) -> Arc<ObbJob> {
        let mut j = ObbJob::from_template(&template_from_vector(0), vector_extranonce(0), id.into()).unwrap();
        j.parents_commitment = [parents_byte; 32];
        Arc::new(j)
    }

    #[test]
    fn store_evicts_and_looks_up() {
        let mut s = JobStore::new(2);
        s.insert(job("a", 1), false);
        s.insert(job("b", 1), false);
        s.insert(job("c", 1), false);
        assert!(s.get("a").is_none());
        assert!(s.get("b").is_some() && s.get("c").is_some());
        assert_eq!(s.len(), 2);
        assert_eq!(s.latest().unwrap().job_id, "c");
    }

    #[test]
    fn clean_jobs_drop_other_tips_only() {
        let mut s = JobStore::new(16);
        s.insert(job("a", 1), false);
        s.insert(job("b", 2), true);
        assert!(s.get("a").is_none(), "a tip change abandons older-tip jobs");
        let mut s = JobStore::new(16);
        s.insert(job("c", 3), false);
        s.insert(job("d", 3), true);
        assert!(s.get("c").is_some(), "a same-tip clean job keeps in-flight jobs valid");
    }

    #[test]
    fn reinserting_an_id_replaces_it() {
        let mut s = JobStore::new(4);
        s.insert(job("a", 1), false);
        s.insert(job("a", 1), false);
        assert_eq!(s.len(), 1);
    }
}

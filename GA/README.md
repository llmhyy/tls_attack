# Genetic Algorithm 
we use GA to search for eligible (accuracy < 0.6) packages.

## process

![process](D:\semester_6\summer_intern\process_GA.png)

- loop in  different generations:

  - loop in one generations,but different individuals:
    1. select some parameters which can be modified as variables in GA.
    2. parameters changed via mutation and cross from their parent generation,and then they are written into setParameter.sh file, to introduce a series of attacks.
    3. capture pcapfiles through attack as one package.
    4. do feature extraction for that package, and process the input data and target
    5. feed into the trained model and calculate its accuracy.

  after the loop for one generation, GA generate a new matrix of parameters for next generation according to accuracy of this generation.

## myproblem.py

1. get matrix of variables, and  record them in x_variable

   ```
   Vars = pop.Phen
   x_variable.append(Vars[:, [i]])
   ```

2.  write these x_variable into parameter.txt according to the specified format. In this example,there are three kind parameters: total number=1+20+1=22

   - window size

   - interval (20)

   - ...

   ```
   4706158
   [244, 855, 105, 1243, 602, 1191, 400, 1708, 1159, 1128, 1600, 1200, 1447, 1348, 1831, 515, 387, 1951, 1174, 1579]
   1485
   ```

3. introduce a series of attack and capture the package in a specified folder

4.  using preprocess. packet function to extract features from package; using preprocess. extract_x function to acquire input x from  the previous step.

5. using utilDtagen. preprocess_data function to normalize x and get target y. then  feed the data into model and calculate accuracy .

6. after processing the whole individuals in this generation, record acc_array in pop.ObjV

   ```
   pop.ObjV = acc_array
   ```

## main.py

use the python lib named geatpy :there are some instructions for use on  http://geatpy.com/ 

**parameter setting**:

```
Encoding = 'RI'       # coding method
NIND = 20           # population capacity
myAlgorithm = GA_traffic.soea_EGA_templet(problem, population)   
myAlgorithm.MAXGEN = 50 # Maximum evolution algebra
```



## GA_traffic.py

define the GA algorithm in details,in this example: Elitist Reservation GA templet

**parameter setting**:

```
self.selFunc = 'tour' # Tournament selection operator
self.mutFunc = 'mutbga' # Mutation operator in GA: real value variation
self.pc = 0.7 # Recombination probability
self.pm = 0.7 # Mutation probability of the entire chromosome

```

## GA_temp

this folder is used to save 'feature extraction' result from package temporarily,  remember to clear this folder before running the main.py

## select_packet

save packages whose accuracy <0.7. 

## temp & sample_packet

these folder are used for adversarial 

## LCS.py

Use  'longest common sequence'  to calculate the similarity of two package.

- **input:** 

  ```
  two sequences (x_1,x_2) ,they are in shape of (1,1000,109)
  valid length (v_len_1,v_len_2),that is :Remove the padded 0 from sequence
  ```

- **output:** 

  similarity has three components: 

  ```
  similarity=r1*r2*sim
  ```

- **r1:** 

  first we extract useful steps in the sequence respectively , we define the useful steps in function judge_lcs. judge_type.  

  r1 is the ratio of useful step in the whole sequence. after this step, we extract a new sequence where all element step is a useful kind, we call them: new_x_1 and new_x_2

- **r2:**  

  we use lcs function to obtain longest subsequence in new_x_1 and new_x_2

  r2 is the ratio of subsequence length in the shorter one of new_x_1/new_x_2

- **sim:** 

  we know element in subsequence is a vector with 109 dimensions, so we calculate the value of  corresponding vectors' cos similarity , sum them and divided by the number.

   
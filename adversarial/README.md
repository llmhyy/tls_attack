# Generate adversarail sequence
for a certain attacked websites, we use a series of packages  cellected in training datasets to generate adversarial samples respectively,
and there are two methods. For example, we have 10 packages for website A, so we can generate 20 adversarial samples, which can be used for GA initialization, diversity of sample will be helpful to find a rational answer.

## 1.main.py
Generate corresponding adversarial samples from  given packages
### input:
* model: 
```
model = load_model(os.path.join(current_dir,'..','rnn-model','trained-rnn','poodle','expt_2019-07-17_16-24-33','rnnmodel_2019-07-17_16-24-33.h5'))
```
* pacage dir: in this example, they are in  GA/sample_packet/(num+1).

```
pcapPath=os.path.join('sample_packet',str(num+1))
```
* save dir: folders to store the result of extracted feature, in this example, they are in GA/temp/(num+1)
```
save_dir=os.path.join('temp',str(num+1))
```
### output；
* norm result : it means adversaarial x with every demension is in range of(0,1); this sequence can be fed into the model directly
* savedir for norm result:  in this example :GA/sample_packet/norm
```
savedir=os.path.join(current_dir,'..','GA','sample_packet','norm')
```
* denorm result: do denormalization for the norm result.the value in this sequence can be implemented in the real feild.
* savedir form denorm result:  in this example :GA/sample_packet/denorm
```
savedir=os.path.join(current_dir,'..','GA','sample_packet','denorm')
```
* acc_{method}.txt: record the origin accuracy for each package
### variable parameters：
* packect_num
* method: 1 or 2,decide which method will be used
```
packet_num=10
method=1
```
### process：
1. locate one package    
2. using preprocess.packet function to extract features from that package,and write result into temp file
3. using preprocess.extract_x function to get input x from temp file,do some dataprocess for x and aquire target
4. generate adversarial sample for x:  
there are two method(you can choose via the parameter 'method'):  
__first__:calculate the derivative about loss to x, then use Gradient rise method to decrease the accuracy.  
__second__: make some small disturbances to the gradient.  

5.using constrain.py to do constrains after every iteration

6.using de_norm function to denormalize the result.
 

### attention：
* pacage dir: Each folder(eg. GA/sample_packect/1) can only contain one package；
* you have to empty the folder GA/temp before start running main.py
* when you choose the second method, then you shouldn't stop it before run over. and if you do that, the next time you start running,there may be some error according to temsorflow graph(because ad_method2 create a new graph). To address this problem,you have to restart the IDE after you Suspended the program  halfway.

## 2. ad_method2.py
in order to generate diverse adversarial sample for a same sample, we use this function to change gradient vector, the cos<> value between the new vector and the original one is within a random range(0.7,0.85). since vector has 109 demensions, it is difficult to control the vector by setting num randomly ,so we use GD method to find the value fastly. 
    
* input: original gradeint in shape of (1,1000,109) ; valid length
* output: generated new gradient

## 3. judge.py
judge the type(eg. client hello,server hello……) for every step, and prepare for the latter constrains.

## 4. constrains.py
constrains rule, Call the function every time a new input x is generated, to ensure that the answer is rational.

## 5. BUGs
* when you choose the second method, then you shouldn't stop it before the program runs over. if you do that, the next time you start running,there may be some error according to temsorflow graph(because ad_method2 create a new graph).  
To address this problem, you have to restart the IDE after you Suspended the program  halfway.





              
              
              

        





